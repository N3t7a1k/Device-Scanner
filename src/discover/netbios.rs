use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use serde_json::json;
use pnet::datalink::{self, NetworkInterface, Channel};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::datalink::MacAddr;
use std::collections::HashMap;

use crate::types::ScanResult;
use crate::logger;

const NETBIOS_PORT: u16 = 137;
const RETRY_COUNT: usize = 3;
const PACKET_DELAY_MS: u64 = 10;
const RETRY_DELAY_MS: u64 = 500;
const WAIT_TIMEOUT_MS: u64 = 2000;

pub async fn scan(interface: &NetworkInterface, targets: &HashMap<IpAddr, MacAddr>) -> Result<()> {
    let interface_ip = interface.ips.iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .context("Interface has no IPv4 address")?;

    let sender_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(interface_ip), 0)).await?;
    let sender_socket = Arc::new(sender_socket);

    let interface_clone = interface.clone();
    
    std::thread::spawn(move || {
        let mut config = datalink::Config::default();
        config.read_timeout = Some(Duration::from_millis(100));

        let (_, mut rx) = match datalink::channel(&interface_clone, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return, 
        };

        loop {
            match rx.next() {
                Ok(packet) => {
                    let eth_packet = EthernetPacket::new(packet).unwrap();
                    
                    if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ip_packet) = Ipv4Packet::new(eth_packet.payload()) {
                            if ip_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
                                if let Some(udp_packet) = UdpPacket::new(ip_packet.payload()) {
                                    if udp_packet.get_source() == NETBIOS_PORT {
                                        
                                        let src_mac = eth_packet.get_source();
                                        let src_ip = IpAddr::V4(ip_packet.get_source());
                                        let payload = udp_packet.payload();

                                        if let Some(hostname) = parse_response(payload) {
                                            let log_entry = ScanResult {
                                                method: "netbios".to_string(),
                                                ip: src_ip.to_string(),
                                                mac: src_mac.to_string(),
                                                result: json!({ "hostname": hostname }),
                                            };
                                            let _ = logger::write(&log_entry);
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                Err(_) => continue,
            }
        }
    });

    let target_ips: Vec<IpAddr> = targets.keys().cloned().collect();

    for _ in 0..RETRY_COUNT {
        for target_ip in &target_ips {
            let target_ipv4 = match target_ip {
                IpAddr::V4(ip) => *ip,
                IpAddr::V6(_) => continue,
            };

            if let Some(packet) = build_netbios_query_packet() {
                let dest = SocketAddr::new(IpAddr::V4(target_ipv4), NETBIOS_PORT);
                let _ = sender_socket.send_to(&packet, dest).await;
            }
            sleep(Duration::from_millis(PACKET_DELAY_MS)).await;
        }
        sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
    }

    sleep(Duration::from_millis(WAIT_TIMEOUT_MS)).await;
    
    Ok(())
}

fn build_netbios_query_packet() -> Option<Vec<u8>> {
    let mut packet = Vec::with_capacity(50);
    
    packet.extend_from_slice(&rand::random::<u16>().to_be_bytes()); 
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); 
    packet.extend_from_slice(&1u16.to_be_bytes()); 
    packet.extend_from_slice(&0u16.to_be_bytes()); 
    packet.extend_from_slice(&0u16.to_be_bytes()); 
    packet.extend_from_slice(&0u16.to_be_bytes()); 

    packet.push(32); 
    packet.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); 
    packet.push(0);

    packet.extend_from_slice(&0x0021u16.to_be_bytes()); 
    packet.extend_from_slice(&0x0001u16.to_be_bytes()); 

    Some(packet)
}

fn parse_response(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 { return None; }
    
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    
    if ancount == 0 { return None; }
    
    let mut offset = 12;
    
    for _ in 0..qdcount {
         loop {
             if offset >= buf.len() { return None; }
             let len = buf[offset] as usize;
             if len == 0 { offset += 1; break; }
             offset += 1 + len;
         }
         offset += 4;
    }
    
    if offset >= buf.len() { return None; }
    
    loop {
         if offset >= buf.len() { return None; }
         let len = buf[offset] as usize;
         if len == 0 { offset += 1; break; }
         if len & 0xC0 == 0xC0 { offset += 2; break; } 
         offset += 1 + len;
    }
    
    if offset + 10 > buf.len() { return None; }
    
    let qtype = u16::from_be_bytes([buf[offset], buf[offset+1]]);
    let rdlength = u16::from_be_bytes([buf[offset+8], buf[offset+9]]) as usize;
    offset += 10;
    
    if qtype == 0x0021 {
        if offset + rdlength > buf.len() { return None; }
        
        let num_names = buf[offset];
        offset += 1;
        
        for _ in 0..num_names {
            if offset + 16 > buf.len() { break; }
            
            let name_bytes = &buf[offset..offset+15]; 
            let _type_byte = buf[offset+15]; 
            
            if let Ok(name) = std::str::from_utf8(name_bytes) {
                let trimmed = name.trim();
                if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    return Some(trimmed.to_string());
                }
            }
            offset += 18; 
        }
    }
    
    None
}

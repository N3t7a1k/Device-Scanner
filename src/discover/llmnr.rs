use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

const LLMNR_PORT: u16 = 5355;
const LLMNR_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
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
                                    if udp_packet.get_source() == LLMNR_PORT || udp_packet.get_destination() == LLMNR_PORT {
                                        
                                        let src_mac = eth_packet.get_source();
                                        let src_ip = IpAddr::V4(ip_packet.get_source());
                                        let payload = udp_packet.payload();

                                        if let Some(hostname) = parse_response(payload) {
                                            let log_entry = ScanResult {
                                                method: "llmnr".to_string(),
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

            if let Some(packet) = build_llmnr_query_packet(IpAddr::V4(target_ipv4)) {
                let dest = SocketAddr::new(IpAddr::V4(LLMNR_MULTICAST_ADDR), LLMNR_PORT);
                let _ = sender_socket.send_to(&packet, dest).await;
            }
            sleep(Duration::from_millis(PACKET_DELAY_MS)).await;
        }
        sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
    }

    sleep(Duration::from_millis(WAIT_TIMEOUT_MS)).await;
    
    Ok(())
}

fn build_llmnr_query_packet(ip: IpAddr) -> Option<Vec<u8>> {
    let name = match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0])
        },
        _ => return None,
    };

    let mut packet = Vec::with_capacity(64);
    
    packet.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    for part in name.split('.') {
        if part.len() > 63 { return None; }
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0);

    packet.extend_from_slice(&12u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // Class IN (1)

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
             if len & 0xC0 == 0xC0 { offset += 2; break; }
             offset += 1 + len;
         }
         offset += 4;
    }
    
    for _ in 0..ancount {
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
         
         if offset + rdlength > buf.len() { return None; }
         
         if qtype == 12 {
             return parse_name(buf, offset);
         }
         
         offset += rdlength;
    }
    None
}

fn parse_name(buf: &[u8], mut offset: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut jumps = 0;
    let max_jumps = 5;
    let mut jumped = false;
    
    loop {
        if jumps > max_jumps { break; }
        if offset >= buf.len() { break; }
        
        let len = buf[offset] as usize;
        
        if len == 0 {
            break;
        } else if len & 0xC0 == 0xC0 {
            if offset + 1 >= buf.len() { return None; }
            let ptr_val = ((len & 0x3F) << 8) | (buf[offset+1] as usize);
            
            if !jumped {
                offset = ptr_val;
                jumped = true;
                jumps += 1;
                continue; 
            } else {
                offset = ptr_val;
                jumps += 1;
                continue;
            }
        }
        
        offset += 1;
        if offset + len > buf.len() { return None; }
        
        let label = &buf[offset..offset+len];
        parts.push(String::from_utf8_lossy(label).to_string());
        
        offset += len;
    }
    
    if parts.is_empty() { return None; }
    
    Some(parts.join("."))
}

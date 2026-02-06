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

const MDNS_PORT: u16 = 5353;
const MDNS_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const RETRY_COUNT: usize = 3;
const PACKET_DELAY_MS: u64 = 10;
const RETRY_DELAY_MS: u64 = 500;
const WAIT_TIMEOUT_MS: u64 = 3000;

const TARGET_SERVICES: &[&str] = &[
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_services._dns-sd._udp.local",
    "_matter._tcp.local",
    "_androidtvremote2._tcp.local",
];

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
                                    if udp_packet.get_source() == MDNS_PORT || udp_packet.get_destination() == MDNS_PORT {
                                        
                                        let src_mac = eth_packet.get_source();
                                        let src_ip = IpAddr::V4(ip_packet.get_source());
                                        let payload = udp_packet.payload();

                                        if let Some(info) = parse_mdns_detailed(payload) {
                                            let final_name = if !info.friendly_name.is_empty() {
                                                info.friendly_name.clone()
                                            } else {
                                                info.hostname.clone()
                                            };

                                            let log_entry = ScanResult {
                                                method: "mdns".to_string(),
                                                ip: src_ip.to_string(),
                                                mac: src_mac.to_string(),
                                                result: json!({ 
                                                    "hostname": final_name,
                                                    "raw_host": info.hostname,
                                                    "meta": info.extras
                                                }),
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
    let dest = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_ADDR), MDNS_PORT);

    for _ in 0..RETRY_COUNT {
        for target_ip in &target_ips {
            let target_ipv4 = match target_ip {
                IpAddr::V4(ip) => *ip,
                IpAddr::V6(_) => continue,
            };

            if let Some(packet) = build_mdns_ptr_packet(IpAddr::V4(target_ipv4)) {
                let _ = sender_socket.send_to(&packet, dest).await;
            }
            sleep(Duration::from_millis(PACKET_DELAY_MS)).await;
        }

        for service in TARGET_SERVICES {
            if let Some(packet) = build_mdns_service_packet(service) {
                let _ = sender_socket.send_to(&packet, dest).await;
            }
            sleep(Duration::from_millis(PACKET_DELAY_MS)).await;
        }

        sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
    }

    sleep(Duration::from_millis(WAIT_TIMEOUT_MS)).await;
    
    Ok(())
}

struct MdnsInfo {
    hostname: String,
    friendly_name: String,
    extras: HashMap<String, String>,
}

fn parse_mdns_detailed(buf: &[u8]) -> Option<MdnsInfo> {
    if buf.len() < 12 { return None; }
    
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let nscount = u16::from_be_bytes([buf[8], buf[9]]); 
    let arcount = u16::from_be_bytes([buf[10], buf[11]]); 
    
    if ancount == 0 && arcount == 0 { return None; }
    
    let mut offset = 12;
    for _ in 0..qdcount {
         offset = skip_name(buf, offset)?;
         offset += 4; 
    }
    
    let mut hostname = String::new();
    let mut extras = HashMap::new();

    let total_records = ancount + nscount + arcount;

    for _ in 0..total_records {
        if offset >= buf.len() { break; }
        offset = skip_name(buf, offset)?;
        if offset + 10 > buf.len() { break; }
        
        let qtype = u16::from_be_bytes([buf[offset], buf[offset+1]]);
        let rdlength = u16::from_be_bytes([buf[offset+8], buf[offset+9]]) as usize;
        offset += 10; 
        
        if offset + rdlength > buf.len() { break; }
        
        match qtype {
            12 => {
                if hostname.is_empty() {
                    if let Some(name) = parse_name(buf, offset) {
                        hostname = name;
                    }
                }
            },
            16 => {
                parse_txt_rdata(buf, offset, rdlength, &mut extras);
            },
            _ => {}
        }
        offset += rdlength;
    }

    if hostname.is_empty() && extras.is_empty() { return None; }

    let friendly_name = extras.get("fn")
        .or_else(|| extras.get("n"))
        .or_else(|| extras.get("md"))
        .or_else(|| extras.get("id"))
        .cloned()
        .unwrap_or_default();

    Some(MdnsInfo { hostname, friendly_name, extras })
}

fn parse_txt_rdata(buf: &[u8], offset: usize, len: usize, map: &mut HashMap<String, String>) {
    let end = offset + len;
    let mut pos = offset;
    while pos < end {
        if pos >= buf.len() { break; }
        let chunk_len = buf[pos] as usize;
        pos += 1;
        if pos + chunk_len > buf.len() || pos + chunk_len > end { break; }

        let chunk = &buf[pos..pos+chunk_len];
        if let Ok(s) = std::str::from_utf8(chunk) {
            if let Some((key, value)) = s.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            }
        }
        pos += chunk_len;
    }
}

fn skip_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= buf.len() { return None; }
        let len = buf[offset] as usize;
        if len == 0 { return Some(offset + 1); }
        if len & 0xC0 == 0xC0 { return Some(offset + 2); }
        offset += 1 + len;
    }
}

fn parse_name(buf: &[u8], mut offset: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut jumps = 0;
    let mut jumped = false;
    loop {
        if jumps > 5 { break; }
        if offset >= buf.len() { break; }
        let len = buf[offset] as usize;
        if len == 0 { break; } 
        else if len & 0xC0 == 0xC0 {
            if offset + 1 >= buf.len() { return None; }
            let ptr_val = ((len & 0x3F) << 8) | (buf[offset+1] as usize);
            if !jumped { offset = ptr_val; jumped = true; jumps += 1; continue; } 
            else { offset = ptr_val; jumps += 1; continue; }
        }
        offset += 1;
        if offset + len > buf.len() { return None; }
        parts.push(String::from_utf8_lossy(&buf[offset..offset+len]).to_string());
        offset += len;
    }
    if parts.is_empty() { return None; }
    Some(parts.join("."))
}

fn build_mdns_ptr_packet(ip: IpAddr) -> Option<Vec<u8>> {
    let name = match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0])
        },
        _ => return None,
    };
    build_query_packet(&name)
}

fn build_mdns_service_packet(service_name: &str) -> Option<Vec<u8>> {
    build_query_packet(service_name)
}

fn build_query_packet(qname: &str) -> Option<Vec<u8>> {
    let mut packet = Vec::with_capacity(64);
    
    packet.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    for part in qname.split('.') {
        if part.len() > 63 { return None; }
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0);

    packet.extend_from_slice(&12u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());

    Some(packet)
}

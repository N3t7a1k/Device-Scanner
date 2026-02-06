use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use serde_json::json;
use pnet::datalink::NetworkInterface;
use pnet::datalink::MacAddr;
use std::collections::HashMap;
use default_net;

use crate::types::ScanResult;
use crate::logger;

const DNS_PORT: u16 = 53;
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

    let all_interfaces = default_net::get_interfaces();
    
    let gateway_ip = all_interfaces.iter()
        .find(|iface| {
            iface.ipv4.iter().any(|net| net.addr.to_string() == interface_ip.to_string())
        })
        .and_then(|iface| iface.gateway.as_ref())
        .map(|gw| gw.ip_addr);

    let gateway_ip = match gateway_ip {
        Some(ip) => ip,
        None => return Ok(()), 
    };

    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(interface_ip), 0)).await?;
    let socket = Arc::new(socket);

    let recv_socket = socket.clone();
    let targets_map = Arc::new(targets.clone());
    
    let listener_handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            if let Ok((size, src)) = recv_socket.recv_from(&mut buf).await {
                if src.ip() == gateway_ip {
                    if let Some((target_ip, hostname)) = parse_dns_response(&buf[..size]) {
                        
                        let mac_addr = targets_map.get(&target_ip)
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| "".to_string());

                        let log_entry = ScanResult {
                            method: "rdns".to_string(),
                            ip: target_ip.to_string(),
                            mac: mac_addr,
                            result: json!({ "hostname": hostname }),
                        };
                        let _ = logger::write(&log_entry);
                    }
                }
            }
        }
    });

    let target_ips: Vec<IpAddr> = targets.keys().cloned().collect();

    for _ in 0..RETRY_COUNT {
        for target_ip in &target_ips {
            if *target_ip == gateway_ip { continue; }

            if let Some(packet) = build_rdns_query_packet(*target_ip) {
                let dest = SocketAddr::new(gateway_ip, DNS_PORT);
                let _ = socket.send_to(&packet, dest).await;
            }
            sleep(Duration::from_millis(PACKET_DELAY_MS)).await;
        }
        sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
    }

    sleep(Duration::from_millis(WAIT_TIMEOUT_MS)).await;
    listener_handle.abort();
    
    Ok(())
}

fn build_rdns_query_packet(ip: IpAddr) -> Option<Vec<u8>> {
    let name = match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0])
        },
        _ => return None,
    };

    let mut packet = Vec::with_capacity(64);
    
    packet.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
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
    packet.extend_from_slice(&1u16.to_be_bytes());

    Some(packet)
}

fn parse_dns_response(buf: &[u8]) -> Option<(IpAddr, String)> {
    if buf.len() < 12 { return None; }
    
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    
    if qdcount == 0 || ancount == 0 { return None; }
    
    let mut offset = 12;
    let mut target_ip_str = String::new();

    for _ in 0..qdcount {
        let qname = parse_name(buf, offset)?; 
        
        loop {
            if offset >= buf.len() { return None; }
            let len = buf[offset] as usize;
            if len == 0 { offset += 1; break; }
            if len & 0xC0 == 0xC0 { offset += 2; break; }
            offset += 1 + len;
        }
        offset += 4;

        if qname.ends_with(".in-addr.arpa") {
             target_ip_str = qname;
        }
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
             let hostname = parse_name(buf, offset)?;
             
             if let Some(ip) = convert_arpa_to_ip(&target_ip_str) {
                 return Some((ip, hostname));
             }
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
        
        if len == 0 { break; } 
        else if len & 0xC0 == 0xC0 {
            if offset + 1 >= buf.len() { return None; }
            let ptr_val = ((len & 0x3F) << 8) | (buf[offset+1] as usize);
            if !jumped { offset = ptr_val; jumped = true; jumps += 1; continue; } 
            else { offset = ptr_val; jumps += 1; continue; }
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

fn convert_arpa_to_ip(arpa: &str) -> Option<IpAddr> {
    let parts: Vec<&str> = arpa.split('.').collect();
    if parts.len() < 4 { return None; }
    
    let d = parts[0].parse::<u8>().ok()?;
    let c = parts[1].parse::<u8>().ok()?;
    let b = parts[2].parse::<u8>().ok()?;
    let a = parts[3].parse::<u8>().ok()?;
    
    Some(IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)))
}

use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use pnet::datalink::{self, NetworkInterface, Channel};
use pnet::packet::{ethernet::{EthernetPacket, EtherTypes}, ipv4::Ipv4Packet, udp::UdpPacket, Packet};
use serde_json::json;
use crate::types::ScanResult;
use crate::logger;

const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

pub async fn listen(iface: &NetworkInterface, stop_signal: Arc<AtomicBool>) -> Result<()> {
    let if_clone = iface.clone();
    
    std::thread::spawn(move || {
        let mut config = datalink::Config::default();
        config.read_timeout = Some(std::time::Duration::from_millis(500));

        let (_, mut rx) = match datalink::channel(&if_clone, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return,
        };

        loop {
            if stop_signal.load(Ordering::SeqCst) { break; }

            if let Ok(pkt) = rx.next() {
                let eth = EthernetPacket::new(pkt).unwrap();
                if eth.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                        if let Some(udp) = UdpPacket::new(ip.payload()) {
                            if udp.get_source() == 68 || udp.get_destination() == 67 {
                                if let Some(hostname) = parse_dhcp_hostname(udp.payload()) {
                                    let _ = logger::write(&ScanResult {
                                        method: "dhcp".into(),
                                        ip: ip.get_source().to_string(),
                                        mac: eth.get_source().to_string(),
                                        result: json!({ "hostname": hostname }),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

fn parse_dhcp_hostname(payload: &[u8]) -> Option<String> {
    if payload.len() < 240 { return None; }
    if payload[236..240] != DHCP_MAGIC_COOKIE { return None; }
    let mut o = 240;
    while o < payload.len() {
        let opt_type = payload[o];
        if opt_type == 255 { break; }
        if opt_type == 0 { o += 1; continue; }
        let opt_len = *payload.get(o + 1)? as usize;
        let start = o + 2;
        let end = start + opt_len;
        if end > payload.len() { break; }
        if opt_type == 12 { return Some(String::from_utf8_lossy(&payload[start..end]).to_string()); }
        o = end;
    }
    None
}

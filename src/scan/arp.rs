use anyhow::{Context, Result, anyhow};
use pnet::datalink::{self, Channel, NetworkInterface, MacAddr};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::HashMap;

const RETRY_COUNT: usize = 3;
const PACKET_DELAY_MS: u64 = 2;

pub async fn scan(interface: &NetworkInterface, target_ips: &[IpAddr]) -> Result<HashMap<IpAddr, MacAddr>> {
    let source_ip = interface.ips.iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .context("Interface does not have an IPv4 address")?;

    let source_mac = interface.mac.context("Interface does not have a MAC address")?;

    let mut config = datalink::Config::default();
    config.read_timeout = Some(Duration::from_millis(100));

    let (mut tx, mut rx) = match datalink::channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow!("Unhandled channel type")),
        Err(e) => return Err(anyhow!("Failed to create channel: {}", e)),
    };

    let active_hosts: Arc<Mutex<HashMap<IpAddr, MacAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let active_hosts_clone = active_hosts.clone();

    let rx_task = std::thread::spawn(move || {
        let mut active_map = HashMap::new();
        let start = Instant::now();
        
        loop {
            if start.elapsed() > Duration::from_secs(5) {
                break;
            }

            match rx.next() {
                Ok(packet) => {
                    let eth_packet = EthernetPacket::new(packet).unwrap();
                    
                    if eth_packet.get_ethertype() == EtherTypes::Arp {
                        let arp_packet = ArpPacket::new(eth_packet.payload()).unwrap();
                        
                        if arp_packet.get_operation() == ArpOperations::Reply {
                            let sender_ip = IpAddr::V4(arp_packet.get_sender_proto_addr());
                            let sender_mac = arp_packet.get_sender_hw_addr();
                            
                            active_map.insert(sender_ip, sender_mac);
                        }
                    }
                },
                Err(_) => continue,
            }
        }
        
        *active_hosts_clone.lock().unwrap() = active_map;
    });

    for _ in 0..RETRY_COUNT {
        for target_ip in target_ips {
            let target_ipv4 = match target_ip {
                IpAddr::V4(ip) => *ip,
                IpAddr::V6(_) => continue,
            };

            if target_ipv4 == source_ip { continue; }

            let mut eth_buffer = [0u8; 42];
            let mut arp_buffer = [0u8; 28];
            
            let mut eth_packet = MutableEthernetPacket::new(&mut eth_buffer).unwrap();
            eth_packet.set_destination(MacAddr::broadcast());
            eth_packet.set_source(source_mac);
            eth_packet.set_ethertype(EtherTypes::Arp);
            
            let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Request);
            arp_packet.set_sender_hw_addr(source_mac);
            arp_packet.set_sender_proto_addr(source_ip);
            arp_packet.set_target_hw_addr(MacAddr::zero());
            arp_packet.set_target_proto_addr(target_ipv4);
            
            eth_packet.set_payload(arp_packet.packet());
            
            tx.send_to(eth_packet.packet(), None);
            tokio::time::sleep(Duration::from_millis(PACKET_DELAY_MS)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    let _ = rx_task.join();

    let hosts = active_hosts.lock().unwrap().clone();
    Ok(hosts)
}

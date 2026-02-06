use anyhow::{Context, Result};
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use std::net::Ipv4Addr;

pub fn get_default_interface() -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();
    
    interfaces
        .into_iter()
        .find(|iface| {
            iface.is_up() 
            && !iface.is_loopback() 
            && !iface.ips.is_empty() 
            && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
        .context("No suitable network interface found")
}

pub fn get_by_name(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .context(format!("Interface '{}' not found", name))
}

pub fn list_interfaces() {
    println!("Available interfaces:");
    for iface in datalink::interfaces() {
        if iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty() {
             println!("- {}: {:?}", iface.name, iface.ips);
        }
    }
}

pub fn get_ipv4_and_prefix(interface: &NetworkInterface) -> Result<(Ipv4Addr, u8)> {
    interface.ips.iter()
        .find_map(|ip| {
            match ip {
                IpNetwork::V4(ipv4_net) => {
                    Some((ipv4_net.ip(), ipv4_net.prefix()))
                }
                _ => None,
            }
        })
        .context("Interface does not have an IPv4 address")
}

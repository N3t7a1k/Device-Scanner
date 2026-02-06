use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use serde_json::json;
use pnet::datalink::{self, NetworkInterface, Channel};
use pnet::packet::{ethernet::{EthernetPacket, EtherTypes}, ipv4::Ipv4Packet, udp::UdpPacket, Packet};
use std::collections::HashMap;
use crate::types::ScanResult;
use crate::logger;

const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

pub async fn scan(iface: &NetworkInterface) -> Result<()> {
    let i_ip = iface.ips.iter().find(|i| i.is_ipv4()).map(|i| match i.ip() { IpAddr::V4(v) => v, _ => unreachable!() }).context("No IPv4")?;
    let sock = Arc::new(UdpSocket::bind(SocketAddr::new(IpAddr::V4(i_ip), 0)).await?);
    let if_clone = iface.clone();

    std::thread::spawn(move || {
        let (_, mut rx) = match datalink::channel(&if_clone, Default::default()) { Ok(Channel::Ethernet(tx, rx)) => (tx, rx), _ => return };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

        loop {
            if let Ok(pkt) = rx.next() {
                let eth = EthernetPacket::new(pkt).unwrap();
                if eth.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                        if let Some(udp) = UdpPacket::new(ip.payload()) {
                            if udp.get_source() == SSDP_PORT || udp.get_destination() == SSDP_PORT {
                                let payload = String::from_utf8_lossy(udp.payload()).to_string();
                                if payload.contains("HTTP/1.1 200 OK") || payload.contains("NOTIFY") {
                                    let src_ip = ip.get_source();
                                    let src_mac = eth.get_source();
                                    
                                    rt.block_on(async {
                                        let _ = process_ssdp_response(src_ip, src_mac, payload).await;
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let query = "M-SEARCH * HTTP/1.1\r\n\
                 HOST: 239.255.255.250:1900\r\n\
                 MAN: \"ssdp:discover\"\r\n\
                 MX: 2\r\n\
                 ST: ssdp:all\r\n\r\n";

    let dest = SocketAddr::new(IpAddr::V4(SSDP_ADDR), SSDP_PORT);
    for _ in 0..3 {
        let _ = sock.send_to(query.as_bytes(), dest).await;
        sleep(Duration::from_millis(500)).await;
    }

    sleep(Duration::from_secs(3)).await;
    Ok(())
}

async fn process_ssdp_response(ip: Ipv4Addr, mac: datalink::MacAddr, payload: String) -> Result<()> {
    let mut headers = HashMap::new();
    for line in payload.lines() {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_uppercase(), v.trim().to_string());
        }
    }

    let mut result_data = json!({
        "server": headers.get("SERVER").unwrap_or(&"".to_string()),
        "st": headers.get("ST").unwrap_or(&"".to_string()),
    });

    if let Some(location) = headers.get("LOCATION") {
        if let Ok(xml_info) = fetch_xml_detail(location).await {
            result_data.as_object_mut().unwrap().insert("details".into(), xml_info);
        }
    }

    let _ = logger::write(&ScanResult {
        method: "ssdp".into(),
        ip: ip.to_string(),
        mac: mac.to_string(),
        result: result_data,
    });

    Ok(())
}

async fn fetch_xml_detail(url: &str) -> Result<serde_json::Value> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build()?;
    let body = client.get(url).send().await?.text().await?;

    let friendly_name = extract_xml_tag(&body, "friendlyName");
    let manufacturer = extract_xml_tag(&body, "manufacturer");
    let model = extract_xml_tag(&body, "modelName");

    Ok(json!({
        "friendly_name": friendly_name,
        "manufacturer": manufacturer,
        "model": model,
        "url": url
    }))
}

fn extract_xml_tag(xml: &str, tag: &str) -> String {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);
    if let Some(start) = xml.find(&start_tag) {
        if let Some(end) = xml.find(&end_tag) {
            return xml[start + start_tag.len()..end].to_string();
        }
    }
    "".to_string()
}

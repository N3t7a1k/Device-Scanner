use anyhow::{Context, Result};
use clap::Parser;
use env_logger::Env;
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use log::info;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

mod discover;
mod interface;
mod logger;
mod scan;
mod types;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to bind (e.g., eth0, wlan0). 
    /// If not specified, the default interface will be selected automatically.
    #[arg(short, long)]
    interface: Option<String>,

    /// Path to the output log file (e.g., scan.log).
    /// If not provided, a filename based on the current date will be used.
    #[arg(short, long)]
    output: Option<String>,

    /// Target to scan. Can be a CIDR (192.168.1.0/24), 
    /// a single IP (192.168.1.5), or a range (192.168.1.1-50).
    #[arg(name = "TARGET")]
    target: Option<String>,

    /// List all available network interfaces on this machine and exit.
    #[arg(short, long)]
    list: bool,
}

impl Args {
    pub fn get_target_ips(&self) -> Result<Vec<IpAddr>> {
        let target = self.target.as_deref().ok_or_else(|| anyhow::anyhow!("Target is not specified."))?;

        if let Ok(net) = target.parse::<IpNetwork>() {
            match net {
                IpNetwork::V4(v4_net) => {
                    if v4_net.prefix() < 31 {
                        return Ok(v4_net.iter()
                            .filter(|ip| *ip != v4_net.network() && *ip != v4_net.broadcast())
                            .map(IpAddr::V4)
                            .collect());
                    } else {
                        return Ok(v4_net.iter().map(IpAddr::V4).collect());
                    }
                },
                IpNetwork::V6(_) => anyhow::bail!("IPv6 not supported."),
            }
        }

        if let Ok(ip) = target.parse::<IpAddr>() {
            if ip.is_ipv6() {
                anyhow::bail!("IPv6 not supported.");
            }
            return Ok(vec![ip]);
        }

        if target.contains('-') {
            let parts: Vec<&str> = target.split('-').collect();
            if parts.len() == 2 {
                let start_str = parts[0].trim();
                let end_str = parts[1].trim();

                let start_ip: Ipv4Addr = start_str.parse()
                    .map_err(|_| anyhow::anyhow!("Invalid start IP format: {}.", start_str))?;

                let end_ip: Ipv4Addr = if let Ok(full_ip) = end_str.parse::<Ipv4Addr>() {
                    full_ip
                } else if let Ok(last_octet) = end_str.parse::<u8>() {
                    let octets = start_ip.octets();
                    Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet)
                } else {
                    anyhow::bail!("Invalid end IP format: {}.", end_str);
                };

                let start_int: u32 = start_ip.into();
                let end_int: u32 = end_ip.into();

                let (min, max) = if start_int < end_int { (start_int, end_int) } else { (end_int, start_int) };

                let mut ips = Vec::new();
                for i in min..=max {
                    ips.push(IpAddr::V4(Ipv4Addr::from(i)));
                }
                
                return Ok(ips);
            }
        }

        anyhow::bail!("Unsupported target format: {}.", target)
    }
}

fn check_privileges() -> Result<()> {
    let interfaces = pnet::datalink::interfaces();
    if let Some(iface) = interfaces.into_iter().find(|i| i.is_up() && !i.is_loopback()) {
        match pnet::datalink::channel(&iface, Default::default()) {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    #[cfg(target_os = "linux")]
                    let msg = format!(
                        "Permission denied. This application requires raw socket privileges.\n\
                        Please run with 'sudo' or set capabilities:\n\
                        sudo setcap cap_net_raw+ep {}", 
                        std::env::current_exe()?.display()
                    );

                    #[cfg(target_os = "windows")]
                    let msg = "Permission denied. Please run this terminal/application as Administrator.".to_string();

                    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                    let msg = "Permission denied. Please run with root/administrator privileges.".to_string();

                    anyhow::bail!(msg);
                }
                Ok(())
            }
        }
    } else {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    if let Err(e) = check_privileges() {
        eprintln!("[Error] {}", e);
        std::process::exit(1);
    }

    let mut args = Args::parse();

    if args.list {
        interface::list_interfaces();
        return Ok(());
    }

    let interface = if args.interface.is_none() {
        let iface = interface::get_default_interface()
            .context("Failed to find default interface.")?;
        info!("Interface not set. Using default interface.");
        args.interface = Some(iface.name.clone());
        iface
    } else {
        let iface_name = args.interface.as_ref().unwrap();
        let iface = interface::get_by_name(iface_name)
            .with_context(|| format!("Interface '{}' not found.", iface_name))?;
        iface
    };
    info!("Interface: {}.", interface.name);

    let log_filename = if args.output.is_none() {
        let filename = logger::get_log_filename();
        info!("Output file not set. Using default filename.");
        filename
    } else {
        args.output.clone().unwrap()
    };
    info!("Output file: {}.", log_filename);
    logger::init(&log_filename)?;

    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_clone = Arc::clone(&stop_signal);

    info!("Start DHCP sniffer in background.");
    discover::dhcp::listen(&interface, stop_signal_clone).await?;

    let ipv4_and_prefix = interface::get_ipv4_and_prefix(&interface)
        .context("No IPv4 address assigned to the interface.")?;
    
    let local_network = Ipv4Network::new(ipv4_and_prefix.0, ipv4_and_prefix.1)
        .context("Invalid local network configuration")?;

    let target_ips: Vec<IpAddr> = if args.target.is_none() {
        local_network.iter()
            .filter(|ip| *ip != local_network.network() && *ip != local_network.broadcast())
            .map(IpAddr::V4)
            .collect()
    }
    else {
        let ips = args.get_target_ips()?;
        if ips.is_empty() {
            anyhow::bail!("No target IPs found.");
        }

        if let (Some(first), Some(last)) = (ips.first(), ips.last()) {
            match (first, last) {
                (IpAddr::V4(f), IpAddr::V4(l)) => {
                    if !local_network.contains(*f) || !local_network.contains(*l) {
                        anyhow::bail!(
                            "Target range ({:?} - {:?}) is outside the local network ({}).", 
                            f, l, local_network
                        );
                    }
                },
                _ => anyhow::bail!("IPv6 not supported."),
            }
        }
        ips
    };
    info!("Target IP count: {}.", target_ips.len());


    info!("Start scanning {} IPs.", target_ips.len());
    let live_ips = scan::arp::scan(&interface, &target_ips)
        .await?;
    info!("Found {} live hosts.", live_ips.len());

    info!("Start mDNS scan.");
    discover::mdns::scan(&interface, &live_ips).await?;
    info!("End mDNS scan.");

    info!("Start LLMNR scan.");
    discover::llmnr::scan(&interface, &live_ips).await?;
    info!("End LLMNR scan.");

    info!("Start NetBIOS scan.");
    discover::netbios::scan(&interface, &live_ips).await?;
    info!("End NetBIOS scan.");

    info!("Start rDNS scan.");
    discover::rdns::scan(&interface, &live_ips).await?;
    info!("End rDNS scan.");

    info!("Start SSDP scan.");
    discover::ssdp::scan(&interface).await?;
    info!("End SSDP scan.");

    info!("All scans completed. Stopping DHCP sniffer.");
    stop_signal.store(true, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    logger::close()?;
    Ok(())
}

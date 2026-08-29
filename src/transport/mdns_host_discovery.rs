//! Browses `_nvstream._tcp.local.` — the service type Jochona Host,
//! Sunshine, and Apollo all advertise (it is the standard NVIDIA GameStream
//! mDNS service type; Jochona Host preserves it for baseline GameStream
//! compatibility) — to find enrollment candidates.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};

const SERVICE_TYPE: &str = "_nvstream._tcp.local.";

#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub instance_name: String,
    pub address: Ipv4Addr,
    pub port: u16,
}

/// Browses for `duration`, returning every distinct instance resolved in
/// that window. A short, bounded scan rather than a long-lived watcher —
/// enrollment is an explicit, admin-triggered action.
pub async fn discover(duration: Duration) -> Result<Vec<DiscoveredHost>> {
    let daemon = ServiceDaemon::new().context("starting mDNS daemon")?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .context("browsing for GameStream hosts")?;

    let mut found = Vec::new();
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let event = tokio::select! {
            event = receiver.recv_async() => event,
            _ = tokio::time::sleep(remaining) => break,
        };
        match event {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(addr) = info.get_addresses().iter().find_map(|a| match a {
                    std::net::IpAddr::V4(v4) => Some(*v4),
                    _ => None,
                }) {
                    found.push(DiscoveredHost {
                        instance_name: info.get_fullname().to_string(),
                        address: addr,
                        port: info.get_port(),
                    });
                }
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    let _ = daemon.stop_browse(SERVICE_TYPE);
    found.sort_by(|a, b| a.instance_name.cmp(&b.instance_name));
    found.dedup_by(|a, b| a.instance_name == b.instance_name);
    Ok(found)
}

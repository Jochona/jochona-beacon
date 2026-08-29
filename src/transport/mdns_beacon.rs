//! Advertises `_jochona-beacon._tcp.local.` on physical LAN interfaces
//! only — never on virtual/tunnel interfaces, matching the same
//! "physical-only" posture as Wake-on-LAN MAC learning
//! (`crate::transport::route`). Overlay/VPN reachability is handled
//! separately by a manually pinned HTTPS URL shown in the admin UI, not by
//! mDNS.

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use uuid::Uuid;

use crate::transport::route::is_physical_interface;

const SERVICE_TYPE: &str = "_jochona-beacon._tcp.local.";

pub struct BeaconAdvertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

impl BeaconAdvertiser {
    /// Starts advertising. `port` is Beacon's HTTPS (mTLS) listener port.
    pub fn start(
        beacon_id: Uuid,
        spki_fingerprint_hex: &str,
        hostname: &str,
        port: u16,
    ) -> Result<Self> {
        let daemon = ServiceDaemon::new().context("starting mDNS daemon")?;

        // Restrict advertisement to physical interfaces: disable everything,
        // then re-enable each interface that passes the same physical-only
        // check used for Wake-on-LAN MAC learning.
        daemon
            .disable_interface(mdns_sd::IfKind::All)
            .context("disabling all mDNS interfaces")?;
        for iface in if_addrs::get_if_addrs().context("enumerating network interfaces")? {
            if iface.is_loopback() {
                continue;
            }
            if is_physical_interface(&iface.name) {
                let _ = daemon.enable_interface(mdns_sd::IfKind::Name(iface.name.clone()));
            }
        }

        let instance_name = beacon_id.to_string();
        let host_fqdn = format!("{hostname}.local.");
        let properties = [
            ("id", beacon_id.to_string()),
            ("fp", spki_fingerprint_hex.to_string()),
            ("v", "1".to_string()),
        ];
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &host_fqdn,
            "",
            port,
            &properties[..],
        )
        .context("building mDNS ServiceInfo")?
        .enable_addr_auto();
        let fullname = service.get_fullname().to_string();
        daemon
            .register(service)
            .context("registering mDNS service")?;

        Ok(Self { daemon, fullname })
    }

    pub fn stop(&self) -> Result<()> {
        self.daemon
            .unregister(&self.fullname)
            .context("unregistering mDNS service")?;
        Ok(())
    }
}

impl Drop for BeaconAdvertiser {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

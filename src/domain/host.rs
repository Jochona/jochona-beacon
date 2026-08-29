use std::net::Ipv4Addr;

use time::OffsetDateTime;
use uuid::Uuid;

/// Which GameStream server implementation a Host runs. Jochona Hosts grant
/// Beacon observer-only permission by construction; Sunshine/Apollo hosts
/// may grant broader control, which we surface as an explicit warning
/// rather than silently accepting elevated trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFamily {
    Jochona,
    Sunshine,
    Apollo,
}

impl HostFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            HostFamily::Jochona => "jochona",
            HostFamily::Sunshine => "sunshine",
            HostFamily::Apollo => "apollo",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "jochona" => Some(HostFamily::Jochona),
            "sunshine" => Some(HostFamily::Sunshine),
            "apollo" => Some(HostFamily::Apollo),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverPermission {
    /// The Host only granted Beacon the ability to observe /serverinfo —
    /// the expected, minimal-trust posture for a Jochona Host.
    ObserverOnly,
    /// The Host's pairing grant was broader than observer-only (this is
    /// normal for stock Sunshine/Apollo, which have no narrower grant to
    /// offer). Surfaced to the admin/CLI as an explicit warning at
    /// enrollment time and persisted so the UI can keep warning.
    BroadPermissionWarning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostState {
    Online,
    Offline,
    Unknown,
}

impl HostState {
    pub fn as_str(self) -> &'static str {
        match self {
            HostState::Online => "online",
            HostState::Offline => "offline",
            HostState::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "online" => HostState::Online,
            "offline" => HostState::Offline,
            _ => HostState::Unknown,
        }
    }
}

/// A registered Host: enrolled once via GameStream observer pairing, then
/// tracked independently for wake targeting and online/offline observation.
#[derive(Clone)]
pub struct Host {
    pub id: Uuid,
    /// The Host's own GameStream `uniqueid`, pinned at enrollment.
    pub gamestream_uuid: String,
    pub name: String,
    pub host_family: HostFamily,
    pub observer_permission: ObserverPermission,
    /// Host's GameStream server certificate (DER), pinned at enrollment;
    /// used to authenticate every later `/serverinfo` observation poll.
    pub cert_der: Vec<u8>,
    /// MAC address learned strictly from a trusted physical-LAN ARP/route
    /// entry — never accepted from a client request.
    pub mac_address: [u8; 6],
    pub learned_interface: String,
    pub http_port: u16,
    pub https_port: u16,
    pub broadcast_address: Ipv4Addr,
    /// Decrypted 6-byte SecureOn password, if the Host's NIC requires one.
    /// Held in memory only; persisted encrypted (see `crypto::secret_box`).
    pub secure_on: Option<[u8; 6]>,
    pub last_state: HostState,
    pub last_observed_at: Option<OffsetDateTime>,
    pub enrolled_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

impl Host {
    pub fn mac_colon_hex(&self) -> String {
        self.mac_address
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

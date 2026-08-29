use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::HostState;

/// Structured events fed to the audit log (`beacon_events` table) and the
/// authenticated SSE stream. Kept as a closed enum (not a free-form map) so
/// every emission site is forced to supply the fields its type promises.
#[derive(Clone, Serialize)]
#[serde(tag = "type")]
pub enum BeaconEvent {
    #[serde(rename = "pairing.opened")]
    PairingOpened {
        pairing_id: Uuid,
        expires_at: String,
    },
    #[serde(rename = "pairing.closed")]
    PairingClosed { pairing_id: Uuid, reason: String },
    #[serde(rename = "client.authorized")]
    ClientAuthorized { fingerprint: String },
    #[serde(rename = "client.revoked")]
    ClientRevoked { fingerprint: String },
    #[serde(rename = "host.enrolled")]
    HostEnrolled {
        host_id: Uuid,
        name: String,
        host_family: String,
        observer_permission: String,
    },
    #[serde(rename = "host.revoked")]
    HostRevoked { host_id: Uuid },
    #[serde(rename = "wake.accepted")]
    WakeAccepted { wake_id: Uuid, host_id: Uuid },
    #[serde(rename = "wake.sent")]
    WakeSent {
        wake_id: Uuid,
        host_id: Uuid,
        burst_index: u8,
    },
    #[serde(rename = "wake.failed")]
    WakeFailed {
        wake_id: Uuid,
        host_id: Uuid,
        error: String,
    },
    #[serde(rename = "host.observed_online")]
    HostObservedOnline { host_id: Uuid },
    #[serde(rename = "host.observed_offline")]
    HostObservedOffline { host_id: Uuid },
    /// Admin-only audit event (never part of the Client-facing wire
    /// contract's `GET /events` type set) recording the identity
    /// hard-block: every authorized Client became unauthorized the
    /// instant this fired.
    #[serde(rename = "identity.regenerated")]
    IdentityRegenerated { beacon_id: Uuid },
}

impl BeaconEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            BeaconEvent::PairingOpened { .. } => "pairing.opened",
            BeaconEvent::PairingClosed { .. } => "pairing.closed",
            BeaconEvent::ClientAuthorized { .. } => "client.authorized",
            BeaconEvent::ClientRevoked { .. } => "client.revoked",
            BeaconEvent::HostEnrolled { .. } => "host.enrolled",
            BeaconEvent::HostRevoked { .. } => "host.revoked",
            BeaconEvent::WakeAccepted { .. } => "wake.accepted",
            BeaconEvent::WakeSent { .. } => "wake.sent",
            BeaconEvent::WakeFailed { .. } => "wake.failed",
            BeaconEvent::HostObservedOnline { .. } => "host.observed_online",
            BeaconEvent::HostObservedOffline { .. } => "host.observed_offline",
            BeaconEvent::IdentityRegenerated { .. } => "identity.regenerated",
        }
    }

    /// Full envelope written to the SSE stream / audit log: `{"type":...,
    /// "at":..., ...fields}`.
    pub fn to_envelope_json(&self, at: OffsetDateTime) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or(serde_json::json!({}));
        if let serde_json::Value::Object(map) = &mut v {
            map.insert(
                "at".to_string(),
                serde_json::Value::String(
                    at.format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                ),
            );
        }
        v
    }
}

pub fn host_state_event(host_id: Uuid, state: HostState) -> Option<BeaconEvent> {
    match state {
        HostState::Online => Some(BeaconEvent::HostObservedOnline { host_id }),
        HostState::Offline => Some(BeaconEvent::HostObservedOffline { host_id }),
        HostState::Unknown => None,
    }
}

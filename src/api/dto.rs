//! Wire shapes for `/jochona/beacon/v1/*`, matching
//! `docs/protocols/client-v1.md` §3 field-for-field. Kept
//! separate from `crate::domain` deliberately: domain types are Beacon's
//! internal vocabulary, these are the locked JSON contract with the
//! Client — the two are allowed to diverge (e.g. the `"sha256:"`-prefixed
//! fingerprint strings here vs. bare hex internally) without either side
//! leaking into the other.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{Host, ObserverPermission};
use crate::storage::repo::time_fmt;

pub fn sha256_prefixed(hex: &str) -> String {
    format!("sha256:{hex}")
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Serialize)]
pub struct PairingInfo {
    pub beacon_id: Uuid,
    pub beacon_fingerprint: String,
    pub pairing_id: Uuid,
    pub expires_at: String,
    pub ciphersuite: &'static str,
}

#[derive(Deserialize)]
pub struct Spake2StartRequest {
    pub client_share: String,
}

#[derive(Serialize)]
pub struct Spake2StartResponse {
    pub beacon_share: String,
    pub beacon_confirm: String,
}

#[derive(Deserialize)]
pub struct Spake2ConfirmRequest {
    pub client_confirm: String,
}

#[derive(Serialize)]
pub struct Spake2ConfirmSuccess {
    pub status: &'static str,
    pub beacon_id: Uuid,
    pub authorized_client_fingerprint: String,
    pub authorized_at: String,
}

#[derive(Serialize)]
pub struct Spake2ConfirmFailure {
    pub status: &'static str,
    pub reason: &'static str,
}

#[derive(Serialize)]
pub struct HostDto {
    pub id: Uuid,
    pub name: String,
    pub host_family: &'static str,
    pub observer_permission: &'static str,
    pub state: &'static str,
    pub last_observed_at: Option<String>,
    pub enrolled_at: String,
}

impl From<Host> for HostDto {
    fn from(h: Host) -> Self {
        HostDto {
            id: h.id,
            name: h.name,
            host_family: h.host_family.as_str(),
            observer_permission: match h.observer_permission {
                ObserverPermission::ObserverOnly => "observer_only",
                ObserverPermission::BroadPermissionWarning => "broad_permission_warning",
            },
            state: h.last_state.as_str(),
            last_observed_at: h.last_observed_at.map(time_fmt::format),
            enrolled_at: time_fmt::format(h.enrolled_at),
        }
    }
}

#[derive(Serialize)]
pub struct WakeAccepted {
    pub wake_id: Uuid,
    pub host_id: Uuid,
    pub status: &'static str,
    pub idempotency_key: String,
}

#[derive(Serialize)]
pub struct WakeStatus {
    pub wake_id: Uuid,
    pub host_id: Uuid,
    pub accepted_at: String,
    pub sent_at: Vec<String>,
    pub failed_at: Option<String>,
    pub error: Option<String>,
}

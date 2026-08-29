//! The periodic authenticated `/serverinfo` observation poll: the *only*
//! source ever allowed to assert a Host is online or offline (never
//! inferred from wake accept/send results — see
//! `crate::domain::HostObservation`). Also backs the one-shot probe run
//! during enrollment (`crate::admin::handlers::enroll_host`), which needs
//! the same pinned request plus the raw XML body to classify the Host's
//! family/permission (`crate::observer::permission::classify`).
//!
//! A Host's IP is *never* stored — only its MAC and the physical interface
//! it was learned on (DHCP leases move; the MAC and the physical-route
//! trust established at enrollment do not). Every poll re-resolves the
//! current IP from the live ARP table (`crate::transport::route`) and
//! simply treats "no longer present on that physical route" as offline
//! rather than an error.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::app::AppState;
use crate::crypto::identity as identity_crypto;
use crate::domain::{host_state_event, Host, HostObservation, HostState, ObservationSource};
use crate::net::http_client;
use crate::storage::repo::{hosts as hosts_repo, observations as observations_repo};
use crate::transport::route;

/// Runs forever, polling every enrolled (non-revoked) Host once per tick.
/// Spawned once from `crate::app::run` as a background task.
pub async fn run_poll_loop(state: AppState) {
    let mut interval = tokio::time::interval(state.config.observer_poll_interval);
    loop {
        interval.tick().await;
        let beacon_unique_id = state.beacon_id().await.to_string();
        let hosts = match hosts_repo::list(&state.db, &state.master_key).await {
            Ok(h) => h,
            Err(err) => {
                tracing::warn!(error = %err, "observer: failed to list hosts for poll");
                continue;
            }
        };
        for host in hosts {
            poll_and_record(&state, &host, &beacon_unique_id).await;
        }
    }
}

async fn poll_and_record(state: &AppState, host: &Host, beacon_unique_id: &str) {
    let online = probe_online(host, beacon_unique_id).await;
    let observed_at = OffsetDateTime::now_utc();
    let new_state = if online {
        HostState::Online
    } else {
        HostState::Offline
    };

    if let Err(err) = observations_repo::record(
        &state.db,
        &HostObservation {
            host_id: host.id,
            observed_at,
            online,
            source: ObservationSource::ServerinfoPoll,
        },
    )
    .await
    {
        tracing::warn!(error = %err, host_id = %host.id, "observer: failed to record observation");
    }

    if new_state != host.last_state {
        if let Err(err) = hosts_repo::update_state(&state.db, host.id, new_state, observed_at).await
        {
            tracing::warn!(error = %err, host_id = %host.id, "observer: failed to update host state");
        }
        if let Some(event) = host_state_event(host.id, new_state) {
            let _ = state.emit_event(event).await;
        }
    }
}

/// `true` only if the pinned `/serverinfo` request against the Host's
/// currently-resolved IP succeeds with HTTP 200. Any failure — physically
/// unreachable, TLS pin mismatch, connection refused, timeout — is treated
/// uniformly as "offline"; Beacon does not attempt to distinguish *why* a
/// Host didn't answer.
pub async fn probe_online(host: &Host, beacon_unique_id: &str) -> bool {
    fetch_serverinfo_for_host(host, beacon_unique_id)
        .await
        .is_ok()
}

/// Resolves the Host's live IP and performs the pinned `/serverinfo` GET,
/// returning the raw XML body. Used by both the poll loop (via
/// `probe_online`) and the enrollment flow, which additionally needs the
/// body to classify the Host (`crate::observer::permission::classify`).
pub async fn fetch_serverinfo_for_host(host: &Host, beacon_unique_id: &str) -> Result<String> {
    let ip = resolve_host_ip(host)?.ok_or_else(|| {
        anyhow!("Host is not currently reachable via a trusted physical LAN route")
    })?;
    let expected_spki = expected_spki_sha256(&host.cert_der)?;
    fetch_serverinfo(ip, host.https_port, expected_spki, beacon_unique_id).await
}

/// Re-resolves a Host's current IP from the live physical ARP table. Never
/// trusts a cached value.
pub fn resolve_host_ip(host: &Host) -> Result<Option<Ipv4Addr>> {
    route::resolve_ip_for_mac(host.mac_address, &host.learned_interface)
}

pub fn expected_spki_sha256(cert_der: &[u8]) -> Result<[u8; 32]> {
    let spki = identity_crypto::subject_public_key_info_der(cert_der)?;
    Ok(Sha256::digest(spki).into())
}

/// Pinned-HTTPS `GET /serverinfo` against an arbitrary (not-yet-enrolled)
/// `ip`/`https_port`/pin — used directly by the enrollment flow, which
/// doesn't have a `Host` row yet.
pub async fn fetch_serverinfo(
    ip: Ipv4Addr,
    https_port: u16,
    expected_spki_sha256: [u8; 32],
    beacon_unique_id: &str,
) -> Result<String> {
    let path = format!("/serverinfo?uniqueid={beacon_unique_id}");
    let resp =
        http_client::get_https_pinned(&ip.to_string(), https_port, &path, expected_spki_sha256)
            .await
            .context("requesting pinned /serverinfo")?;
    if resp.status != 200 {
        bail!("Host /serverinfo returned HTTP {}", resp.status);
    }
    String::from_utf8(resp.body).context("/serverinfo response is not valid UTF-8")
}

/// Extracts the Host's own persistent GameStream `<uniqueid>` from a
/// `/serverinfo` body — the value pinned into `hosts.gamestream_uuid` at
/// enrollment so re-enrollment of the same physical Host is recognized as
/// such rather than creating a duplicate row.
pub fn extract_uniqueid(serverinfo_xml: &str) -> Result<String> {
    let doc = roxmltree::Document::parse(serverinfo_xml)
        .context("/serverinfo response is not valid XML")?;
    let node = doc
        .root_element()
        .descendants()
        .find(|n| n.has_tag_name("uniqueid"))
        .ok_or_else(|| anyhow!("/serverinfo response is missing <uniqueid>"))?;
    let text = node.text().unwrap_or_default().trim();
    if text.is_empty() {
        bail!("/serverinfo <uniqueid> is empty");
    }
    Ok(text.to_string())
}

/// Default interval between poll sweeps if not overridden by config.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_uniqueid_from_serverinfo_xml() {
        let xml = r#"<root status_code="200"><uniqueid>ABCD-1234</uniqueid><hostname>pc</hostname></root>"#;
        assert_eq!(extract_uniqueid(xml).unwrap(), "ABCD-1234");
    }

    #[test]
    fn rejects_serverinfo_xml_missing_uniqueid() {
        let xml = r#"<root status_code="200"><hostname>pc</hostname></root>"#;
        assert!(extract_uniqueid(xml).is_err());
    }
}

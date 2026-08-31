//! The server-owned 0s/1s/3s Wake-on-LAN burst schedule. Spawned exactly
//! once per newly-*accepted* `wake_events` row
//! (`crate::api::routes::wake::wake_host`) — an idempotency-key replay
//! never reaches this function, so one accepted request always produces
//! exactly one fresh burst schedule, never more.
//!
//! The schedule itself only ever lives inside one spawned in-memory task,
//! so a daemon crash/restart mid-burst leaves the `wake_events` row
//! durably "accepted" with no way for the original task to ever finish
//! it. `resume_incomplete_wakes` runs once at startup
//! (`crate::app::run`) to recover exactly those rows, so a wake's status
//! never sits accepted-but-unresolved forever.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::AppState;
use crate::domain::{BeaconEvent, Host};
use crate::storage::repo::hosts as hosts_repo;
use crate::storage::repo::wake_events as wake_events_repo;
use crate::transport::wake as wake_transport;

pub async fn run_burst(state: AppState, wake_id: Uuid, host: Host) {
    run_burst_from(state, wake_id, host, 0).await;
}

/// Runs the burst schedule starting at `start_index` — `0` for a
/// brand-new wake (`run_burst`'s only caller), or the count of bursts
/// already recorded `sent_at` when resuming one abandoned by a crash.
/// Delays are counted fresh from this call's own start, not the wake's
/// original `accepted_at`: after a resume, "0s/1s/3s spaced apart from
/// right now" is the only interpretation of the schedule that still
/// means anything, since the original absolute offsets are long past.
async fn run_burst_from(state: AppState, wake_id: Uuid, host: Host, start_index: usize) {
    let packet = wake_transport::build_magic_packet(&host.mac_address, host.secure_on.as_ref());
    let started_at = tokio::time::Instant::now();

    for (index, offset_secs) in wake_transport::BURST_DELAYS_SECONDS
        .into_iter()
        .enumerate()
        .skip(start_index)
    {
        tokio::time::sleep_until(started_at + std::time::Duration::from_secs(offset_secs)).await;

        match wake_transport::send_burst(host.broadcast_address, wake_transport::WOL_PORT, &packet)
            .await
        {
            Ok(()) => {
                let at = OffsetDateTime::now_utc();
                if let Err(err) = wake_events_repo::record_sent(&state.db, wake_id, at).await {
                    tracing::error!(error = %err, %wake_id, "failed to record wake burst send");
                }
                let _ = state
                    .emit_event(BeaconEvent::WakeSent {
                        wake_id,
                        host_id: host.id,
                        burst_index: index as u8,
                    })
                    .await;
            }
            Err(err) => {
                let at = OffsetDateTime::now_utc();
                let error_message = err.to_string();
                if let Err(record_err) =
                    wake_events_repo::record_failed(&state.db, wake_id, at, &error_message).await
                {
                    tracing::error!(error = %record_err, %wake_id, "failed to record wake burst failure");
                }
                let _ = state
                    .emit_event(BeaconEvent::WakeFailed {
                        wake_id,
                        host_id: host.id,
                        error: error_message,
                    })
                    .await;
                // Sending itself failed (socket error) — stop rather than
                // retry the remaining bursts; `failed_at`/`error` are a
                // single column each, not a per-burst log.
                return;
            }
        }
    }
}

/// Recovers every wake abandoned mid-burst by a crash/restart: rows with
/// no `failed_at` and fewer than the full three-burst schedule's
/// `sent_at` entries. A missing or revoked Host can't be resumed, so
/// that case is resolved to a truthful, terminal `record_failed` instead
/// of being left accepted forever. Called once from `crate::app::run` at
/// startup, before any new wake requests can arrive.
pub async fn resume_incomplete_wakes(state: AppState) {
    let incomplete = match wake_events_repo::list_incomplete(&state.db).await {
        Ok(events) => events,
        Err(err) => {
            tracing::error!(error = %err, "wake recovery: failed to list incomplete wake_events");
            return;
        }
    };

    for event in incomplete {
        let already_sent = event.sent_at.len();
        if already_sent >= wake_transport::BURST_DELAYS_SECONDS.len() {
            continue;
        }

        let host = match hosts_repo::get(&state.db, &state.master_key, event.host_id).await {
            Ok(Some(host)) if host.revoked_at.is_none() => host,
            Ok(_) => {
                tracing::warn!(
                    wake_id = %event.id,
                    host_id = %event.host_id,
                    "wake recovery: host no longer enrolled, marking wake permanently failed"
                );
                if let Err(err) = wake_events_repo::record_failed(
                    &state.db,
                    event.id,
                    OffsetDateTime::now_utc(),
                    "host was revoked or removed before this wake completed",
                )
                .await
                {
                    tracing::error!(error = %err, wake_id = %event.id, "wake recovery: failed to record terminal failure");
                }
                continue;
            }
            Err(err) => {
                tracing::error!(error = %err, wake_id = %event.id, "wake recovery: failed to load host, leaving for the next restart");
                continue;
            }
        };

        tracing::info!(
            wake_id = %event.id,
            host_id = %host.id,
            resumed_from_burst = already_sent,
            "wake recovery: resuming a wake abandoned by a prior crash/restart"
        );
        tokio::spawn(run_burst_from(state.clone(), event.id, host, already_sent));
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::app::test_app_state;
    use crate::domain::{HostFamily, HostState, ObserverPermission, WakeEvent};
    use crate::storage::Db;

    fn test_host(id: Uuid) -> Host {
        Host {
            id,
            gamestream_uuid: format!("host-{id}"),
            name: "Test Host".to_string(),
            host_family: HostFamily::Jochona,
            observer_permission: ObserverPermission::ObserverOnly,
            cert_der: vec![1, 2, 3],
            mac_address: [0, 1, 2, 3, 4, 5],
            learned_interface: "en0".to_string(),
            http_port: 47989,
            https_port: 47984,
            // Loopback: real broadcast doesn't work here, but sending to
            // 127.0.0.1 exercises the exact same socket-creation/SO_BROADCAST/
            // send_to path without needing a real LAN segment (matches
            // `crate::transport::wake`'s own test convention) and must not
            // error.
            broadcast_address: Ipv4Addr::new(127, 0, 0, 1),
            secure_on: None,
            last_state: HostState::Unknown,
            last_observed_at: None,
            enrolled_at: OffsetDateTime::now_utc(),
            revoked_at: None,
        }
    }

    fn abandoned_wake(wake_id: Uuid, host_id: Uuid) -> WakeEvent {
        // Exactly the state a crash leaves behind: durably accepted, zero
        // bursts ever sent — whether because the daemon died before
        // `run_burst` ran a single iteration, or (the now-fixed bug)
        // `emit_event` failed before the burst was even scheduled.
        WakeEvent {
            id: wake_id,
            host_id,
            requested_by_fingerprint: "test-fp".to_string(),
            idempotency_key: "test-key".to_string(),
            accepted_at: OffsetDateTime::now_utc(),
            sent_at: Vec::new(),
            failed_at: None,
            error: None,
        }
    }

    #[tokio::test]
    async fn resume_incomplete_wakes_completes_a_wake_abandoned_before_any_burst_was_sent() {
        let db = Db::open_in_memory().unwrap();
        let state = test_app_state(db.clone()).await.unwrap();

        let host = test_host(Uuid::new_v4());
        hosts_repo::insert(&db, &state.master_key, &host)
            .await
            .unwrap();
        let wake_id = Uuid::new_v4();
        wake_events_repo::insert_accepted(&db, &abandoned_wake(wake_id, host.id))
            .await
            .unwrap();

        resume_incomplete_wakes(state).await;

        // `resume_incomplete_wakes` only spawns the recovered burst; give
        // its full (short, 0s/1s/3s) schedule time to finish.
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;

        let resolved = wake_events_repo::get(&db, wake_id).await.unwrap().unwrap();
        assert_eq!(
            resolved.sent_at.len(),
            wake_transport::BURST_DELAYS_SECONDS.len(),
            "a wake abandoned before any burst was sent must still complete every burst on recovery"
        );
        assert!(resolved.failed_at.is_none());
    }

    #[tokio::test]
    async fn resume_incomplete_wakes_terminally_fails_a_wake_whose_host_is_gone() {
        let db = Db::open_in_memory().unwrap();
        let state = test_app_state(db.clone()).await.unwrap();

        let host = test_host(Uuid::new_v4());
        hosts_repo::insert(&db, &state.master_key, &host)
            .await
            .unwrap();
        hosts_repo::revoke(&db, host.id).await.unwrap();
        let wake_id = Uuid::new_v4();
        wake_events_repo::insert_accepted(&db, &abandoned_wake(wake_id, host.id))
            .await
            .unwrap();

        resume_incomplete_wakes(state).await;

        let resolved = wake_events_repo::get(&db, wake_id).await.unwrap().unwrap();
        assert!(
            resolved.failed_at.is_some(),
            "a wake whose host disappeared before recovery must resolve to a truthful failure, never stay accepted forever"
        );
        assert!(resolved.sent_at.is_empty());
    }

    #[tokio::test]
    async fn resume_incomplete_wakes_skips_a_wake_that_already_finished() {
        let db = Db::open_in_memory().unwrap();
        let state = test_app_state(db.clone()).await.unwrap();

        let host = test_host(Uuid::new_v4());
        hosts_repo::insert(&db, &state.master_key, &host)
            .await
            .unwrap();
        let wake_id = Uuid::new_v4();
        wake_events_repo::insert_accepted(&db, &abandoned_wake(wake_id, host.id))
            .await
            .unwrap();
        for _ in 0..wake_transport::BURST_DELAYS_SECONDS.len() {
            wake_events_repo::record_sent(&db, wake_id, OffsetDateTime::now_utc())
                .await
                .unwrap();
        }

        resume_incomplete_wakes(state).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let resolved = wake_events_repo::get(&db, wake_id).await.unwrap().unwrap();
        assert_eq!(
            resolved.sent_at.len(),
            wake_transport::BURST_DELAYS_SECONDS.len(),
            "an already-complete wake must not be re-sent or otherwise mutated by recovery"
        );
    }
}

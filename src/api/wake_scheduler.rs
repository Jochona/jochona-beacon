//! The server-owned 0s/1s/3s Wake-on-LAN burst schedule. Spawned exactly
//! once per newly-*accepted* `wake_events` row
//! (`crate::api::routes::wake::wake_host`) — an idempotency-key replay
//! never reaches this function, so one accepted request always produces
//! exactly one burst schedule, never more.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::AppState;
use crate::domain::{BeaconEvent, Host};
use crate::storage::repo::wake_events as wake_events_repo;
use crate::transport::wake as wake_transport;

pub async fn run_burst(state: AppState, wake_id: Uuid, host: Host) {
    let packet = wake_transport::build_magic_packet(&host.mac_address, host.secure_on.as_ref());
    let started_at = tokio::time::Instant::now();

    for (index, offset_secs) in wake_transport::BURST_DELAYS_SECONDS.into_iter().enumerate() {
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

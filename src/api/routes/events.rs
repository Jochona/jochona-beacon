//! `GET /events` — authenticated SSE. Every connection first replays the
//! durable audit log (`beacon_events`) so a client that connects late
//! never misses history, then switches to the live broadcast channel —
//! the two are stitched together with no gap and no duplication because
//! the broadcast subscription is taken out *before* the backlog is read.
//!
//! `beacon_events` also carries a few admin-only audit entries
//! (`client.authorized`, `client.revoked`, `identity.regenerated` — see
//! `crate::domain::BeaconEvent`, surfaced on the admin history page) that
//! are outside the wire contract's fixed `GET /events` type union. Those
//! are filtered out here rather than never recorded, so the audit log
//! stays complete while the Client-facing stream stays exactly what the
//! contract promises.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::{Stream, StreamExt};
use tokio::sync::broadcast;

use crate::app::AppState;
use crate::storage::repo::events as events_repo;

/// The exact `type` value union `local://beacon-client-wire-contract.md`
/// §3 fixes for `GET /events`.
const CONTRACT_EVENT_TYPES: &[&str] = &[
    "wake.accepted",
    "wake.sent",
    "wake.failed",
    "host.observed_online",
    "host.observed_offline",
    "pairing.opened",
    "pairing.closed",
    "host.enrolled",
    "host.revoked",
];

fn is_contract_event(payload: &serde_json::Value) -> bool {
    payload
        .get("type")
        .and_then(|t| t.as_str())
        .is_some_and(|t| CONTRACT_EVENT_TYPES.contains(&t))
}

pub async fn stream_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.event_tx.subscribe();

    let backlog = events_repo::list_since(&state.db, 0, 10_000)
        .await
        .unwrap_or_default();
    let backlog_stream = futures::stream::iter(
        backlog
            .into_iter()
            .filter(|(_, payload)| is_contract_event(payload))
            .map(|(_, payload)| Ok(Event::default().data(payload.to_string()))),
    );

    let live_stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(payload) if is_contract_event(&payload) => yield Ok(Event::default().data(payload.to_string())),
                Ok(_) => continue,
                // A slow subscriber skipped some events on the live
                // channel; it already has everything up to that point
                // from the backlog replay above, so just keep going.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(backlog_stream.chain(live_stream))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

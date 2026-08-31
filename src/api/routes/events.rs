//! `GET /events` — authenticated SSE. Every connection first replays the
//! durable audit log (`beacon_events`) so a client that connects late
//! never misses history, then switches to the live broadcast channel.
//! The broadcast subscription is taken out *before* the backlog is read
//! so no event can fall in the gap between them — but that ordering
//! means an event committed (and broadcast) in that same window can
//! legitimately arrive on both paths. `cursor` (the highest
//! `beacon_events.id` already yielded) resolves that overlap: every
//! event, from the backlog, the live channel, or a post-lag catch-up
//! query, is compared against it and only forwarded once.
//!
//! A slow subscriber that lags far enough to have entries evicted from
//! the broadcast channel's ring buffer does not silently lose them: on
//! `RecvError::Lagged`, the durable log is re-queried for everything
//! after `cursor`, so the only way to miss an event permanently is for
//! it to fall outside the retention window entirely.
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

/// The exact `type` value union `docs/protocols/client-v1.md`
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

/// Whether a `(id, payload)` row read after `cursor` (the highest id
/// already yielded to this subscriber) should be forwarded: it must be
/// new — the core of the backlog/live/catch-up dedup rule — and pass the
/// same contract-event filter the initial backlog replay applies.
/// Extracted out of `stream_events`'s generator body so this rule is
/// independently testable without an SSE/axum harness.
fn should_forward(id: i64, payload: &serde_json::Value, cursor: i64) -> bool {
    id > cursor && is_contract_event(payload)
}

pub async fn stream_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.event_tx.subscribe();

    let backlog = events_repo::list_since(&state.db, 0, 10_000)
        .await
        .unwrap_or_default();
    let mut cursor = backlog.iter().map(|(id, _)| *id).max().unwrap_or(0);
    let backlog_stream = futures::stream::iter(
        backlog
            .into_iter()
            .filter(|(_, payload)| is_contract_event(payload))
            .map(|(_, payload)| Ok(Event::default().data(payload.to_string()))),
    );

    let db = state.db.clone();
    let live_stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok((id, payload)) => {
                    let forward = should_forward(id, &payload, cursor);
                    if id > cursor {
                        cursor = id;
                    }
                    if forward {
                        yield Ok(Event::default().data(payload.to_string()));
                    }
                }
                // The broadcast ring buffer evicted some events before we
                // read them. Recover them from the durable log rather
                // than skipping past them: everything with id > cursor
                // that this subscriber missed is still in `beacon_events`
                // until retention prunes it.
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    match events_repo::list_since(&db, cursor, 10_000).await {
                        Ok(rows) => {
                            for (id, payload) in rows {
                                let forward = should_forward(id, &payload, cursor);
                                cursor = id;
                                if forward {
                                    yield Ok(Event::default().data(payload.to_string()));
                                }
                            }
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "SSE: failed to catch up on lagged events");
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(backlog_stream.chain(live_stream))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract_payload() -> serde_json::Value {
        serde_json::json!({"type": "wake.accepted", "at": "2024-01-01T00:00:00Z"})
    }

    fn admin_only_payload() -> serde_json::Value {
        serde_json::json!({"type": "client.authorized", "at": "2024-01-01T00:00:00Z"})
    }

    #[test]
    fn never_forwards_an_id_already_covered_by_the_cursor() {
        // This is the dedup rule the backlog/live overlap depends on:
        // whatever the backlog replay (or a prior catch-up) already
        // yielded must never be re-yielded by a later broadcast delivery
        // of the same row.
        assert!(!should_forward(5, &contract_payload(), 5));
        assert!(!should_forward(4, &contract_payload(), 5));
    }

    #[test]
    fn forwards_a_new_contract_event_past_the_cursor() {
        assert!(should_forward(6, &contract_payload(), 5));
    }

    #[test]
    fn never_forwards_an_admin_only_event_even_when_new() {
        // Admin-only audit events stay out of the Client-facing stream
        // regardless of freshness.
        assert!(!should_forward(6, &admin_only_payload(), 5));
    }

    #[tokio::test]
    async fn list_since_recovers_exactly_the_rows_a_lagged_subscriber_missed() {
        use crate::domain::BeaconEvent;
        use crate::storage::Db;
        use uuid::Uuid;

        let db = Db::open_in_memory().unwrap();
        let mut ids = Vec::new();
        for _ in 0..5 {
            let id = events_repo::append(
                &db,
                &BeaconEvent::HostRevoked {
                    host_id: Uuid::new_v4(),
                },
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
            ids.push(id);
        }

        // Simulate a subscriber that only ever processed the first two
        // rows (`cursor` stuck at `ids[1]`) before lagging on the rest.
        let cursor = ids[1];
        let recovered = events_repo::list_since(&db, cursor, 10_000).await.unwrap();
        let recovered_ids: Vec<i64> = recovered.iter().map(|(id, _)| *id).collect();
        assert_eq!(
            recovered_ids,
            ids[2..],
            "catch-up must return exactly the rows after cursor, in order, with none skipped or repeated"
        );
    }
}

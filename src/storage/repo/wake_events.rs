use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::WakeEvent;
use crate::storage::repo::time_fmt;
use crate::storage::Db;

struct RawWakeRow {
    id: String,
    host_id: String,
    requested_by_fingerprint: String,
    idempotency_key: String,
    accepted_at: String,
    sent_at_json: String,
    failed_at: Option<String>,
    error: Option<String>,
}

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawWakeRow> {
    Ok(RawWakeRow {
        id: row.get("id")?,
        host_id: row.get("host_id")?,
        requested_by_fingerprint: row.get("requested_by_fingerprint")?,
        idempotency_key: row.get("idempotency_key")?,
        accepted_at: row.get("accepted_at")?,
        sent_at_json: row.get("sent_at_json")?,
        failed_at: row.get("failed_at")?,
        error: row.get("error")?,
    })
}

fn decode(raw: RawWakeRow) -> Result<WakeEvent> {
    let sent_at_strs: Vec<String> =
        serde_json::from_str(&raw.sent_at_json).context("parsing sent_at_json")?;
    let sent_at = sent_at_strs
        .iter()
        .map(|s| time_fmt::parse(s))
        .collect::<Result<Vec<_>>>()?;
    Ok(WakeEvent {
        id: Uuid::parse_str(&raw.id).context("stored wake_id is not a valid UUID")?,
        host_id: Uuid::parse_str(&raw.host_id).context("stored host_id is not a valid UUID")?,
        requested_by_fingerprint: raw.requested_by_fingerprint,
        idempotency_key: raw.idempotency_key,
        accepted_at: time_fmt::parse(&raw.accepted_at)?,
        sent_at,
        failed_at: raw.failed_at.as_deref().map(time_fmt::parse).transpose()?,
        error: raw.error,
    })
}

/// Looks up a previously accepted wake by its idempotency tuple. A hit
/// means the caller should return the *original* recorded result verbatim
/// instead of sending new magic packets.
pub async fn find_by_idempotency(
    db: &Db,
    requested_by_fingerprint: &str,
    host_id: Uuid,
    idempotency_key: &str,
) -> Result<Option<WakeEvent>> {
    let fp = requested_by_fingerprint.to_string();
    let host_id_str = host_id.to_string();
    let key = idempotency_key.to_string();
    let raw: Option<RawWakeRow> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT * FROM wake_events WHERE requested_by_fingerprint = ?1 AND host_id = ?2 AND idempotency_key = ?3",
                params![fp, host_id_str, key],
                row_to_raw,
            )
            .optional()
            .context("querying wake_events by idempotency key")
        })
        .await?;
    raw.map(decode).transpose()
}

pub async fn get(db: &Db, wake_id: Uuid) -> Result<Option<WakeEvent>> {
    let id_str = wake_id.to_string();
    let raw: Option<RawWakeRow> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT * FROM wake_events WHERE id = ?1",
                params![id_str],
                row_to_raw,
            )
            .optional()
            .context("querying wake_events")
        })
        .await?;
    raw.map(decode).transpose()
}

pub async fn insert_accepted(db: &Db, event: &WakeEvent) -> Result<()> {
    let id = event.id.to_string();
    let host_id = event.host_id.to_string();
    let fp = event.requested_by_fingerprint.clone();
    let key = event.idempotency_key.clone();
    let accepted_at = time_fmt::format(event.accepted_at);
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO wake_events (id, host_id, requested_by_fingerprint, idempotency_key, accepted_at, sent_at_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, '[]')",
            params![id, host_id, fp, key, accepted_at],
        )
        .context("inserting wake_events row")?;
        Ok(())
    })
    .await
}

/// Appends one burst timestamp. Called once per magic-packet burst (0s/1s/3s).
pub async fn record_sent(db: &Db, wake_id: Uuid, at: OffsetDateTime) -> Result<()> {
    let id_str = wake_id.to_string();
    let at_str = time_fmt::format(at);
    db.call(move |conn| {
        let current: String = conn.query_row(
            "SELECT sent_at_json FROM wake_events WHERE id = ?1",
            params![id_str],
            |r| r.get(0),
        )?;
        let mut list: Vec<String> = serde_json::from_str(&current).unwrap_or_default();
        list.push(at_str);
        let updated = serde_json::to_string(&list)?;
        conn.execute(
            "UPDATE wake_events SET sent_at_json = ?1 WHERE id = ?2",
            params![updated, wake_id.to_string()],
        )?;
        Ok(())
    })
    .await
}

pub async fn record_failed(db: &Db, wake_id: Uuid, at: OffsetDateTime, error: &str) -> Result<()> {
    let id_str = wake_id.to_string();
    let at_str = time_fmt::format(at);
    let error = error.to_string();
    db.call(move |conn| {
        conn.execute(
            "UPDATE wake_events SET failed_at = ?1, error = ?2 WHERE id = ?3",
            params![at_str, error, id_str],
        )?;
        Ok(())
    })
    .await
}

/// Most recent wake attempts across every Host, newest first — backs the
/// admin history page (not part of the Client-facing wire contract, which
/// only ever looks up one `wake_id` at a time via `GET /wake/:wake_id`).
pub async fn list_recent(db: &Db, limit: i64) -> Result<Vec<WakeEvent>> {
    let raws: Vec<RawWakeRow> = db
        .call(move |conn| {
            let mut stmt =
                conn.prepare("SELECT * FROM wake_events ORDER BY accepted_at DESC LIMIT ?1")?;
            let rows = stmt
                .query_map(params![limit], row_to_raw)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("reading wake_events")?;
            Ok(rows)
        })
        .await?;
    raws.into_iter().map(decode).collect()
}

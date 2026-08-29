use anyhow::{Context, Result};
use rusqlite::params;
use time::OffsetDateTime;

use crate::domain::BeaconEvent;
use crate::storage::repo::time_fmt;
use crate::storage::Db;

/// Appends one structured event to the audit log / SSE backlog. Returns the
/// SQLite rowid, used by the SSE route as a resumable cursor.
pub async fn append(db: &Db, event: &BeaconEvent, at: OffsetDateTime) -> Result<i64> {
    let event_type = event.event_type().to_string();
    let payload = event.to_envelope_json(at).to_string();
    let created_at = time_fmt::format(at);
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO beacon_events (event_type, payload_json, created_at) VALUES (?1, ?2, ?3)",
            params![event_type, payload, created_at],
        )
        .context("inserting beacon_events row")?;
        Ok(conn.last_insert_rowid())
    })
    .await
}

/// Events with rowid greater than `cursor`, oldest first — used both to
/// prime a newly-connected SSE stream (`cursor = 0`) and to resume one.
pub async fn list_since(db: &Db, cursor: i64, limit: i64) -> Result<Vec<(i64, serde_json::Value)>> {
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, payload_json FROM beacon_events WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![cursor, limit], |row| {
                let id: i64 = row.get(0)?;
                let payload: String = row.get(1)?;
                Ok((id, payload))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("reading beacon_events")?;
        rows.into_iter()
            .map(|(id, payload)| {
                Ok((
                    id,
                    serde_json::from_str(&payload).context("parsing stored event payload")?,
                ))
            })
            .collect()
    })
    .await
}

/// Retention pruning (30-day default, configurable) for the audit log.
pub async fn prune_older_than(db: &Db, cutoff: OffsetDateTime) -> Result<u64> {
    let cutoff_str = time_fmt::format(cutoff);
    db.call(move |conn| {
        let n = conn.execute(
            "DELETE FROM beacon_events WHERE created_at < ?1",
            params![cutoff_str],
        )?;
        Ok(n as u64)
    })
    .await
}

/// Deletes every retained event/observation immediately — backs the admin
/// "clear history" action.
pub async fn clear_all(db: &Db) -> Result<()> {
    db.call(|conn| {
        conn.execute("DELETE FROM beacon_events", [])?;
        conn.execute("DELETE FROM host_observations", [])?;
        Ok(())
    })
    .await
}

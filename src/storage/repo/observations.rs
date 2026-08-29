use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{HostObservation, ObservationSource};
use crate::storage::repo::time_fmt;
use crate::storage::Db;

/// Records one independent online/offline data point. Never called from the
/// wake path — only from the periodic `/serverinfo` observer poll (or once
/// at enrollment) — see `crate::observer::gamestream`.
pub async fn record(db: &Db, obs: &HostObservation) -> Result<()> {
    let host_id = obs.host_id.to_string();
    let observed_at = time_fmt::format(obs.observed_at);
    let online = obs.online as i64;
    let source = obs.source.as_str().to_string();
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO host_observations (host_id, observed_at, online, source) VALUES (?1, ?2, ?3, ?4)",
            params![host_id, observed_at, online, source],
        )
        .context("inserting host_observations row")?;
        Ok(())
    })
    .await
}

pub async fn latest_for_host(db: &Db, host_id: Uuid) -> Result<Option<HostObservation>> {
    let id_str = host_id.to_string();
    let row: Option<(String, i64, String)> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT observed_at, online, source FROM host_observations WHERE host_id = ?1 ORDER BY observed_at DESC LIMIT 1",
                params![id_str],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .context("querying latest host_observations")
        })
        .await?;
    match row {
        None => Ok(None),
        Some((observed_at, online, source)) => Ok(Some(HostObservation {
            host_id,
            observed_at: time_fmt::parse(&observed_at)?,
            online: online != 0,
            source: match source.as_str() {
                "serverinfo_poll" => ObservationSource::ServerinfoPoll,
                _ => ObservationSource::Enrollment,
            },
        })),
    }
}

/// 30-day-default configurable retention: deletes observations older than
/// `cutoff`, returning the count removed.
pub async fn prune_older_than(db: &Db, cutoff: OffsetDateTime) -> Result<u64> {
    let cutoff_str = time_fmt::format(cutoff);
    db.call(move |conn| {
        let n = conn.execute(
            "DELETE FROM host_observations WHERE observed_at < ?1",
            params![cutoff_str],
        )?;
        Ok(n as u64)
    })
    .await
}

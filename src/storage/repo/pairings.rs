use anyhow::{Context, Result};
use rand::Rng;
use rusqlite::{params, OptionalExtension};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::spake2_pairing;
use crate::domain::{PairingPhase, PairingSession};
use crate::storage::repo::time_fmt;
use crate::storage::Db;

const WINDOW_SECONDS: i64 = 60;

struct RawPairingRow {
    id: String,
    short_code: String,
    salt: Vec<u8>,
    phase: String,
    beacon_scalar_y: Option<Vec<u8>>,
    client_share_pa: Option<Vec<u8>>,
    beacon_share_pb: Option<Vec<u8>>,
    client_identity_a: Option<String>,
    attempts: i64,
    opened_at: String,
    expires_at: String,
}

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawPairingRow> {
    Ok(RawPairingRow {
        id: row.get("id")?,
        short_code: row.get("short_code")?,
        salt: row.get("salt")?,
        phase: row.get("phase")?,
        beacon_scalar_y: row.get("beacon_scalar_y")?,
        client_share_pa: row.get("client_share_pa")?,
        beacon_share_pb: row.get("beacon_share_pb")?,
        client_identity_a: row.get("client_identity_a")?,
        attempts: row.get("attempts")?,
        opened_at: row.get("opened_at")?,
        expires_at: row.get("expires_at")?,
    })
}

fn decode(raw: RawPairingRow) -> Result<PairingSession> {
    Ok(PairingSession {
        id: Uuid::parse_str(&raw.id).context("stored pairing_id is not a valid UUID")?,
        short_code: raw.short_code,
        salt: raw.salt,
        phase: PairingPhase::parse(&raw.phase).context("stored pairing phase is invalid")?,
        beacon_scalar_y: raw.beacon_scalar_y,
        client_share_pa: raw.client_share_pa,
        beacon_share_pb: raw.beacon_share_pb,
        client_identity_a: raw.client_identity_a,
        attempts: raw.attempts as u32,
        opened_at: time_fmt::parse(&raw.opened_at)?,
        expires_at: time_fmt::parse(&raw.expires_at)?,
    })
}

fn random_short_code() -> String {
    // 8-digit decimal, zero-padded; drawn from a CSPRNG (never a raw PSK —
    // this only ever feeds the scrypt-based `w` derivation, see
    // crypto::spake2_pairing).
    let n: u32 = rand::thread_rng().gen_range(0..100_000_000);
    format!("{n:08}")
}

/// Opens a fresh 60-second pairing window, closing any prior open/started
/// window first (Beacon exposes at most one pairing window at a time).
pub async fn open_window(db: &Db, beacon_id: Uuid) -> Result<(PairingSession, String)> {
    let pairing_id = Uuid::new_v4();
    let short_code = random_short_code();
    let salt = spake2_pairing::compute_salt(beacon_id, pairing_id);
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::seconds(WINDOW_SECONDS);

    let id_str = pairing_id.to_string();
    let opened_at_str = time_fmt::format(now);
    let expires_at_str = time_fmt::format(expires_at);
    let short_code_clone = short_code.clone();
    let salt_clone = salt.clone();

    db.call(move |conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM pairing_sessions WHERE phase IN ('open', 'started')", [])?;
        tx.execute(
            "INSERT INTO pairing_sessions (id, short_code, salt, phase, attempts, opened_at, expires_at) \
             VALUES (?1, ?2, ?3, 'open', 0, ?4, ?5)",
            params![id_str, short_code_clone, salt_clone, opened_at_str, expires_at_str],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await
    .context("opening pairing window")?;

    Ok((
        PairingSession {
            id: pairing_id,
            short_code: short_code.clone(),
            salt,
            phase: PairingPhase::Open,
            beacon_scalar_y: None,
            client_share_pa: None,
            beacon_share_pb: None,
            client_identity_a: None,
            attempts: 0,
            opened_at: now,
            expires_at,
        },
        short_code,
    ))
}

pub async fn get(db: &Db, pairing_id: Uuid) -> Result<Option<PairingSession>> {
    let id_str = pairing_id.to_string();
    let raw: Option<RawPairingRow> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT * FROM pairing_sessions WHERE id = ?1",
                params![id_str],
                row_to_raw,
            )
            .optional()
            .context("querying pairing_sessions")
        })
        .await?;
    raw.map(decode).transpose()
}

/// The single currently-open (non-expired) window, if any — backs
/// `GET /jochona/beacon/v1/pairing`.
pub async fn current_open(db: &Db) -> Result<Option<PairingSession>> {
    let now_str = time_fmt::format(OffsetDateTime::now_utc());
    let raw: Option<RawPairingRow> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT * FROM pairing_sessions WHERE phase IN ('open','started') AND expires_at > ?1 \
                 ORDER BY opened_at DESC LIMIT 1",
                params![now_str],
                row_to_raw,
            )
            .optional()
            .context("querying current pairing window")
        })
        .await?;
    raw.map(decode).transpose()
}

/// Records round 1: the client's `pA`, its derived identity string, and
/// Beacon's own `(y, pB)` — everything `/confirm` needs to recompute `K`.
#[allow(clippy::too_many_arguments)]
pub async fn record_started(
    db: &Db,
    pairing_id: Uuid,
    client_identity_a: &str,
    client_share_pa: &[u8],
    beacon_scalar_y: &[u8],
    beacon_share_pb: &[u8],
) -> Result<bool> {
    let id_str = pairing_id.to_string();
    let a = client_identity_a.to_string();
    let pa = client_share_pa.to_vec();
    let y = beacon_scalar_y.to_vec();
    let pb = beacon_share_pb.to_vec();
    let now = time_fmt::format(OffsetDateTime::now_utc());
    db.call(move |conn| {
        let changed = conn.execute(
            "UPDATE pairing_sessions SET phase = 'started', client_identity_a = ?1, client_share_pa = ?2, \
                beacon_scalar_y = ?3, beacon_share_pb = ?4, attempts = attempts + 1 \
             WHERE id = ?5 AND phase = 'open' AND expires_at > ?6",
            params![a, pa, y, pb, id_str, now],
        )?;
        Ok(changed == 1)
    })
    .await
}

/// Terminal transition: pairing succeeded or failed. Either way the window
/// is closed — a leaked or guessed short code gets exactly one attempt.
pub async fn close(db: &Db, pairing_id: Uuid) -> Result<()> {
    let id_str = pairing_id.to_string();
    db.call(move |conn| {
        conn.execute(
            "DELETE FROM pairing_sessions WHERE id = ?1",
            params![id_str],
        )?;
        Ok(())
    })
    .await
}

/// Periodic sweep for windows nobody ever finished; returns the count removed.
pub async fn sweep_expired(db: &Db) -> Result<u64> {
    let now_str = time_fmt::format(OffsetDateTime::now_utc());
    db.call(move |conn| {
        let n = conn.execute(
            "DELETE FROM pairing_sessions WHERE expires_at <= ?1",
            params![now_str],
        )?;
        Ok(n as u64)
    })
    .await
}

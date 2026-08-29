use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};

use crate::domain::AuthorizedClient;
use crate::storage::repo::time_fmt;
use crate::storage::Db;

struct RawClientRow {
    id: i64,
    spki_fingerprint: String,
    cert_der: Vec<u8>,
    label: Option<String>,
    authorized_since_beacon_identity: String,
    authorized_at: String,
    revoked_at: Option<String>,
}

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawClientRow> {
    Ok(RawClientRow {
        id: row.get("id")?,
        spki_fingerprint: row.get("spki_fingerprint")?,
        cert_der: row.get("cert_der")?,
        label: row.get("label")?,
        authorized_since_beacon_identity: row.get("authorized_since_beacon_identity")?,
        authorized_at: row.get("authorized_at")?,
        revoked_at: row.get("revoked_at")?,
    })
}

fn decode(raw: RawClientRow) -> Result<AuthorizedClient> {
    Ok(AuthorizedClient {
        id: raw.id,
        spki_fingerprint: raw.spki_fingerprint,
        cert_der: raw.cert_der,
        label: raw.label,
        authorized_since_beacon_identity: raw.authorized_since_beacon_identity,
        authorized_at: time_fmt::parse(&raw.authorized_at)?,
        revoked_at: raw.revoked_at.as_deref().map(time_fmt::parse).transpose()?,
    })
}

/// Authorizes a client certificate immediately after a successful SPAKE2
/// confirmation. Idempotent on `spki_fingerprint`: re-pairing the same
/// certificate simply refreshes its authorization (clears any prior
/// revocation and re-binds it to the current beacon identity).
pub async fn authorize(
    db: &Db,
    spki_fingerprint: &str,
    cert_der: &[u8],
    label: Option<&str>,
    beacon_id: &str,
) -> Result<()> {
    let authorized_at = time_fmt::format(time::OffsetDateTime::now_utc());
    let spki_fingerprint = spki_fingerprint.to_string();
    let cert_der = cert_der.to_vec();
    let label = label.map(|s| s.to_string());
    let beacon_id = beacon_id.to_string();
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO authorized_clients \
                (spki_fingerprint, cert_der, label, authorized_since_beacon_identity, authorized_at, revoked_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL) \
             ON CONFLICT(spki_fingerprint) DO UPDATE SET \
                cert_der = excluded.cert_der, \
                label = COALESCE(excluded.label, authorized_clients.label), \
                authorized_since_beacon_identity = excluded.authorized_since_beacon_identity, \
                authorized_at = excluded.authorized_at, \
                revoked_at = NULL",
            params![spki_fingerprint, cert_der, label, beacon_id, authorized_at],
        )
        .context("authorizing client certificate")?;
        Ok(())
    })
    .await
}

pub async fn find_by_fingerprint(
    db: &Db,
    spki_fingerprint: &str,
) -> Result<Option<AuthorizedClient>> {
    let fp = spki_fingerprint.to_string();
    let raw: Option<RawClientRow> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT * FROM authorized_clients WHERE spki_fingerprint = ?1",
                params![fp],
                row_to_raw,
            )
            .optional()
            .context("querying authorized_clients")
        })
        .await?;
    raw.map(decode).transpose()
}

pub async fn list(db: &Db) -> Result<Vec<AuthorizedClient>> {
    let raws: Vec<RawClientRow> = db
        .call(|conn| {
            let mut stmt =
                conn.prepare("SELECT * FROM authorized_clients ORDER BY authorized_at DESC")?;
            let rows = stmt
                .query_map([], row_to_raw)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("reading authorized_clients")?;
            Ok(rows)
        })
        .await?;
    raws.into_iter().map(decode).collect()
}

pub async fn revoke(db: &Db, spki_fingerprint: &str) -> Result<bool> {
    let fp = spki_fingerprint.to_string();
    let revoked_at = time_fmt::format(time::OffsetDateTime::now_utc());
    db.call(move |conn| {
        let changed = conn.execute(
            "UPDATE authorized_clients SET revoked_at = ?1 WHERE spki_fingerprint = ?2 AND revoked_at IS NULL",
            params![revoked_at, fp],
        )?;
        Ok(changed > 0)
    })
    .await
}

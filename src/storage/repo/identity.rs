use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use crate::crypto::identity as identity_crypto;
use crate::crypto::master_key::MasterKey;
use crate::domain::BeaconIdentity;
use crate::storage::repo::time_fmt;
use crate::storage::{secret_box, Db};

const AAD: &[u8] = b"beacon_identity.key_ciphertext";

/// Plain column values, decoded with no fallible crypto inside the
/// `rusqlite` row-mapping closure — decryption happens afterwards in
/// ordinary `anyhow`-flavored code, which keeps every repo function's error
/// handling uniform instead of nesting `rusqlite::Result<anyhow::Result<_>>`.
struct RawIdentityRow {
    beacon_id: String,
    cert_der: Vec<u8>,
    key_ciphertext: Vec<u8>,
    key_nonce: Vec<u8>,
    created_at: String,
}

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawIdentityRow> {
    Ok(RawIdentityRow {
        beacon_id: row.get("beacon_id")?,
        cert_der: row.get("cert_der")?,
        key_ciphertext: row.get("key_ciphertext")?,
        key_nonce: row.get("key_nonce")?,
        created_at: row.get("created_at")?,
    })
}

fn decode(raw: RawIdentityRow, master_key: &MasterKey) -> Result<BeaconIdentity> {
    let beacon_id =
        Uuid::parse_str(&raw.beacon_id).context("stored beacon_id is not a valid UUID")?;
    let key_pkcs8_der = secret_box::open(master_key, AAD, &raw.key_ciphertext, &raw.key_nonce)
        .context("decrypting beacon identity private key (wrong master key?)")?;
    Ok(BeaconIdentity {
        beacon_id,
        cert_der: raw.cert_der,
        key_pkcs8_der,
        created_at: time_fmt::parse(&raw.created_at)?,
    })
}

/// Loads the singleton identity row, generating and persisting a fresh one
/// on first run.
pub async fn load_or_create(db: &Db, master_key: MasterKey) -> Result<BeaconIdentity> {
    let existing_raw: Option<RawIdentityRow> = db
        .call(|conn| {
            conn.query_row("SELECT * FROM beacon_identity WHERE id = 1", [], row_to_raw)
                .optional()
                .context("querying beacon_identity")
        })
        .await?;

    if let Some(raw) = existing_raw {
        return decode(raw, &master_key);
    }

    let beacon_id = Uuid::new_v4();
    let generated = identity_crypto::generate_self_signed(beacon_id)?;
    let sealed = secret_box::seal(&master_key, AAD, &generated.key_pkcs8_der)?;
    let created_at = time_fmt::format(time::OffsetDateTime::now_utc());

    db.call({
        let cert_der = generated.cert_der.clone();
        let beacon_id_str = beacon_id.to_string();
        let created_at = created_at.clone();
        move |conn| {
            conn.execute(
                "INSERT INTO beacon_identity (id, beacon_id, cert_der, key_ciphertext, key_nonce, created_at) \
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                params![beacon_id_str, cert_der, sealed.ciphertext, sealed.nonce, created_at],
            )
            .context("inserting beacon_identity")?;
            Ok(())
        }
    })
    .await?;

    Ok(BeaconIdentity {
        beacon_id,
        cert_der: generated.cert_der,
        key_pkcs8_der: generated.key_pkcs8_der,
        created_at: time_fmt::parse(&created_at)?,
    })
}

/// Regenerates Beacon's identity. This is the "hard block": every
/// previously authorized client's `authorized_since_beacon_identity` now
/// points at a stale beacon id, so `AuthorizedClient::is_active` rejects it
/// on the very next mTLS handshake without any separate revoke pass.
pub async fn regenerate(db: &Db, master_key: MasterKey) -> Result<BeaconIdentity> {
    let beacon_id = Uuid::new_v4();
    let generated = identity_crypto::generate_self_signed(beacon_id)?;
    let sealed = secret_box::seal(&master_key, AAD, &generated.key_pkcs8_der)?;
    let created_at = time_fmt::format(time::OffsetDateTime::now_utc());

    db.call({
        let cert_der = generated.cert_der.clone();
        let beacon_id_str = beacon_id.to_string();
        let created_at = created_at.clone();
        move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO beacon_identity (id, beacon_id, cert_der, key_ciphertext, key_nonce, created_at) \
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                params![beacon_id_str, cert_der, sealed.ciphertext, sealed.nonce, created_at],
            )
            .context("replacing beacon_identity")?;
            Ok(())
        }
    })
    .await?;

    Ok(BeaconIdentity {
        beacon_id,
        cert_der: generated.cert_der,
        key_pkcs8_der: generated.key_pkcs8_der,
        created_at: time_fmt::parse(&created_at)?,
    })
}

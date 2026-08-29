use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};

use crate::crypto::gamestream_pairing::{self, GameStreamIdentity};
use crate::crypto::master_key::MasterKey;
use crate::storage::repo::time_fmt;
use crate::storage::{secret_box, Db};

const AAD: &[u8] = b"gamestream_identity.key_ciphertext";

struct RawRow {
    cert_der: Vec<u8>,
    cert_pem: String,
    key_ciphertext: Vec<u8>,
    key_nonce: Vec<u8>,
}

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawRow> {
    Ok(RawRow {
        cert_der: row.get("cert_der")?,
        cert_pem: row.get("cert_pem")?,
        key_ciphertext: row.get("key_ciphertext")?,
        key_nonce: row.get("key_nonce")?,
    })
}

fn decode(raw: RawRow, master_key: &MasterKey) -> Result<GameStreamIdentity> {
    let key_pkcs8_der = secret_box::open(master_key, AAD, &raw.key_ciphertext, &raw.key_nonce)
        .context("decrypting GameStream pairing private key (wrong master key?)")?;
    Ok(GameStreamIdentity {
        cert_der: raw.cert_der,
        cert_pem: raw.cert_pem,
        key_pkcs8_der,
    })
}

/// Loads the singleton GameStream observer-pairing identity, generating and
/// persisting a fresh one on first use. Unlike `repo::identity`, there is
/// no regeneration path — Hosts pin this certificate, so replacing it would
/// silently strand every enrolled Host.
pub async fn load_or_create(db: &Db, master_key: MasterKey) -> Result<GameStreamIdentity> {
    let existing: Option<RawRow> = db
        .call(|conn| {
            conn.query_row(
                "SELECT * FROM gamestream_identity WHERE id = 1",
                [],
                row_to_raw,
            )
            .optional()
            .context("querying gamestream_identity")
        })
        .await?;

    if let Some(raw) = existing {
        return decode(raw, &master_key);
    }

    let generated = gamestream_pairing::generate_identity()?;
    let sealed = secret_box::seal(&master_key, AAD, &generated.key_pkcs8_der)?;
    let created_at = time_fmt::format(time::OffsetDateTime::now_utc());

    db.call({
        let cert_der = generated.cert_der.clone();
        let cert_pem = generated.cert_pem.clone();
        move |conn| {
            conn.execute(
                "INSERT INTO gamestream_identity (id, cert_der, cert_pem, key_ciphertext, key_nonce, created_at) \
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                params![cert_der, cert_pem, sealed.ciphertext, sealed.nonce, created_at],
            )
            .context("inserting gamestream_identity")?;
            Ok(())
        }
    })
    .await?;

    Ok(generated)
}

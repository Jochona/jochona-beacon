use std::net::Ipv4Addr;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use rusqlite::{params, OptionalExtension};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::master_key::MasterKey;
use crate::domain::{Host, HostFamily, HostState, ObserverPermission};
use crate::storage::repo::time_fmt;
use crate::storage::{secret_box, Db};

fn secure_on_aad(host_id: Uuid) -> Vec<u8> {
    format!("hosts.secure_on:{host_id}").into_bytes()
}

struct RawHostRow {
    id: String,
    gamestream_uuid: String,
    name: String,
    host_family: String,
    observer_permission: String,
    cert_der: Vec<u8>,
    mac_address: String,
    learned_interface: String,
    http_port: i64,
    https_port: i64,
    broadcast_address: String,
    secure_on_ciphertext: Option<Vec<u8>>,
    secure_on_nonce: Option<Vec<u8>>,
    last_state: String,
    last_observed_at: Option<String>,
    enrolled_at: String,
    revoked_at: Option<String>,
}

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawHostRow> {
    Ok(RawHostRow {
        id: row.get("id")?,
        gamestream_uuid: row.get("gamestream_uuid")?,
        name: row.get("name")?,
        host_family: row.get("host_family")?,
        observer_permission: row.get("observer_permission")?,
        cert_der: row.get("cert_der")?,
        mac_address: row.get("mac_address")?,
        learned_interface: row.get("learned_interface")?,
        http_port: row.get("http_port")?,
        https_port: row.get("https_port")?,
        broadcast_address: row.get("broadcast_address")?,
        secure_on_ciphertext: row.get("secure_on_ciphertext")?,
        secure_on_nonce: row.get("secure_on_nonce")?,
        last_state: row.get("last_state")?,
        last_observed_at: row.get("last_observed_at")?,
        enrolled_at: row.get("enrolled_at")?,
        revoked_at: row.get("revoked_at")?,
    })
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("stored MAC address {s:?} is malformed");
    }
    for (i, part) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("stored MAC address {s:?} is malformed"))?;
    }
    Ok(out)
}

fn decode(raw: RawHostRow, master_key: &MasterKey) -> Result<Host> {
    let id = Uuid::parse_str(&raw.id).context("stored host id is not a valid UUID")?;
    let secure_on = match (raw.secure_on_ciphertext, raw.secure_on_nonce) {
        (Some(ct), Some(nonce)) => {
            let plain = secret_box::open(master_key, &secure_on_aad(id), &ct, &nonce)
                .context("decrypting SecureOn password (wrong master key?)")?;
            if plain.len() != 6 {
                bail!(
                    "decrypted SecureOn password must be 6 bytes, got {}",
                    plain.len()
                );
            }
            let mut arr = [0u8; 6];
            arr.copy_from_slice(&plain);
            Some(arr)
        }
        _ => None,
    };

    Ok(Host {
        id,
        gamestream_uuid: raw.gamestream_uuid,
        name: raw.name,
        host_family: HostFamily::parse(&raw.host_family)
            .context("stored host_family is invalid")?,
        observer_permission: match raw.observer_permission.as_str() {
            "observer_only" => ObserverPermission::ObserverOnly,
            "broad_permission_warning" => ObserverPermission::BroadPermissionWarning,
            other => bail!("stored observer_permission {other:?} is invalid"),
        },
        cert_der: raw.cert_der,
        mac_address: parse_mac(&raw.mac_address)?,
        learned_interface: raw.learned_interface,
        http_port: raw.http_port as u16,
        https_port: raw.https_port as u16,
        broadcast_address: Ipv4Addr::from_str(&raw.broadcast_address)
            .context("stored broadcast_address is invalid")?,
        secure_on,
        last_state: HostState::parse(&raw.last_state),
        last_observed_at: raw
            .last_observed_at
            .as_deref()
            .map(time_fmt::parse)
            .transpose()?,
        enrolled_at: time_fmt::parse(&raw.enrolled_at)?,
        revoked_at: raw.revoked_at.as_deref().map(time_fmt::parse).transpose()?,
    })
}

pub async fn insert(db: &Db, master_key: &MasterKey, host: &Host) -> Result<()> {
    let sealed_secure_on = host
        .secure_on
        .map(|so| secret_box::seal(master_key, &secure_on_aad(host.id), &so))
        .transpose()?;

    let id = host.id.to_string();
    let gamestream_uuid = host.gamestream_uuid.clone();
    let name = host.name.clone();
    let host_family = host.host_family.as_str().to_string();
    let observer_permission = match host.observer_permission {
        ObserverPermission::ObserverOnly => "observer_only",
        ObserverPermission::BroadPermissionWarning => "broad_permission_warning",
    }
    .to_string();
    let cert_der = host.cert_der.clone();
    let mac_address = host.mac_colon_hex();
    let learned_interface = host.learned_interface.clone();
    let http_port = host.http_port as i64;
    let https_port = host.https_port as i64;
    let broadcast_address = host.broadcast_address.to_string();
    let (secure_on_ciphertext, secure_on_nonce) = match sealed_secure_on {
        Some(s) => (Some(s.ciphertext), Some(s.nonce)),
        None => (None, None),
    };
    let enrolled_at = time_fmt::format(host.enrolled_at);

    db.call(move |conn| {
        conn.execute(
            "INSERT INTO hosts (id, gamestream_uuid, name, host_family, observer_permission, cert_der, \
                mac_address, learned_interface, http_port, https_port, broadcast_address, \
                secure_on_ciphertext, secure_on_nonce, last_state, enrolled_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'unknown',?14)",
            params![
                id,
                gamestream_uuid,
                name,
                host_family,
                observer_permission,
                cert_der,
                mac_address,
                learned_interface,
                http_port,
                https_port,
                broadcast_address,
                secure_on_ciphertext,
                secure_on_nonce,
                enrolled_at,
            ],
        )
        .context("inserting host")?;
        Ok(())
    })
    .await
}

/// Enrolls a Host, or — if a row with this `gamestream_uuid` already
/// exists — refreshes it in place. The original row ID remains stable so
/// wake history and AEAD associated data continue to reference one Host.
///
/// @return The persisted Host ID, which can differ from `host.id` during
/// re-enrollment.
pub async fn upsert_by_gamestream_uuid(
    db: &Db,
    master_key: &MasterKey,
    host: &Host,
) -> Result<Uuid> {
    let lookup_uuid = host.gamestream_uuid.clone();
    let existing_id: Option<String> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT id FROM hosts WHERE gamestream_uuid = ?1",
                params![lookup_uuid],
                |row| row.get(0),
            )
            .optional()
            .context("querying existing Host ID")
        })
        .await?;
    let persisted_id = existing_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .context("stored Host ID is not a valid UUID")?
        .unwrap_or(host.id);
    let sealed_secure_on = host
        .secure_on
        .map(|so| secret_box::seal(master_key, &secure_on_aad(persisted_id), &so))
        .transpose()?;

    let id = persisted_id.to_string();
    let gamestream_uuid = host.gamestream_uuid.clone();
    let name = host.name.clone();
    let host_family = host.host_family.as_str().to_string();
    let observer_permission = match host.observer_permission {
        ObserverPermission::ObserverOnly => "observer_only",
        ObserverPermission::BroadPermissionWarning => "broad_permission_warning",
    }
    .to_string();
    let cert_der = host.cert_der.clone();
    let mac_address = host.mac_colon_hex();
    let learned_interface = host.learned_interface.clone();
    let http_port = host.http_port as i64;
    let https_port = host.https_port as i64;
    let broadcast_address = host.broadcast_address.to_string();
    let (secure_on_ciphertext, secure_on_nonce) = match sealed_secure_on {
        Some(s) => (Some(s.ciphertext), Some(s.nonce)),
        None => (None, None),
    };
    let enrolled_at = time_fmt::format(host.enrolled_at);

    db.call(move |conn| {
        conn.execute(
            "INSERT INTO hosts (id, gamestream_uuid, name, host_family, observer_permission, cert_der, \
                mac_address, learned_interface, http_port, https_port, broadcast_address, \
                secure_on_ciphertext, secure_on_nonce, last_state, enrolled_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'unknown',?14) \
             ON CONFLICT(gamestream_uuid) DO UPDATE SET \
                name = excluded.name, \
                host_family = excluded.host_family, \
                observer_permission = excluded.observer_permission, \
                cert_der = excluded.cert_der, \
                mac_address = excluded.mac_address, \
                learned_interface = excluded.learned_interface, \
                http_port = excluded.http_port, \
                https_port = excluded.https_port, \
                broadcast_address = excluded.broadcast_address, \
                secure_on_ciphertext = excluded.secure_on_ciphertext, \
                secure_on_nonce = excluded.secure_on_nonce, \
                last_state = 'unknown', \
                last_observed_at = NULL, \
                enrolled_at = excluded.enrolled_at, \
                revoked_at = NULL",
            params![
                id,
                gamestream_uuid,
                name,
                host_family,
                observer_permission,
                cert_der,
                mac_address,
                learned_interface,
                http_port,
                https_port,
                broadcast_address,
                secure_on_ciphertext,
                secure_on_nonce,
                enrolled_at,
            ],
        )
        .context("upserting host by gamestream_uuid")?;
        Ok(())
    })
    .await?;
    Ok(persisted_id)
}

pub async fn get(db: &Db, master_key: &MasterKey, id: Uuid) -> Result<Option<Host>> {
    let id_str = id.to_string();
    let raw: Option<RawHostRow> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT * FROM hosts WHERE id = ?1",
                params![id_str],
                row_to_raw,
            )
            .optional()
            .context("querying hosts")
        })
        .await?;
    raw.map(|r| decode(r, master_key)).transpose()
}

pub async fn find_by_gamestream_uuid(
    db: &Db,
    master_key: &MasterKey,
    gamestream_uuid: &str,
) -> Result<Option<Host>> {
    let gs = gamestream_uuid.to_string();
    let raw: Option<RawHostRow> = db
        .call(move |conn| {
            conn.query_row(
                "SELECT * FROM hosts WHERE gamestream_uuid = ?1",
                params![gs],
                row_to_raw,
            )
            .optional()
            .context("querying hosts by gamestream_uuid")
        })
        .await?;
    raw.map(|r| decode(r, master_key)).transpose()
}

pub async fn list(db: &Db, master_key: &MasterKey) -> Result<Vec<Host>> {
    let raws: Vec<RawHostRow> = db
        .call(|conn| {
            let mut stmt = conn.prepare(
                "SELECT * FROM hosts WHERE revoked_at IS NULL ORDER BY enrolled_at DESC",
            )?;
            let rows = stmt
                .query_map([], row_to_raw)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("reading hosts")?;
            Ok(rows)
        })
        .await?;
    raws.into_iter().map(|r| decode(r, master_key)).collect()
}

pub async fn update_state(
    db: &Db,
    id: Uuid,
    state: HostState,
    observed_at: OffsetDateTime,
) -> Result<()> {
    let id_str = id.to_string();
    let state_str = state.as_str().to_string();
    let observed_at_str = time_fmt::format(observed_at);
    db.call(move |conn| {
        conn.execute(
            "UPDATE hosts SET last_state = ?1, last_observed_at = ?2 WHERE id = ?3",
            params![state_str, observed_at_str, id_str],
        )?;
        Ok(())
    })
    .await
}

pub async fn revoke(db: &Db, id: Uuid) -> Result<bool> {
    let id_str = id.to_string();
    let revoked_at = time_fmt::format(OffsetDateTime::now_utc());
    db.call(move |conn| {
        let changed = conn.execute(
            "UPDATE hosts SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
            params![revoked_at, id_str],
        )?;
        Ok(changed > 0)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_host(id: Uuid, secure_on: [u8; 6]) -> Host {
        Host {
            id,
            gamestream_uuid: "stable-host".to_string(),
            name: "Test Host".to_string(),
            host_family: HostFamily::Jochona,
            observer_permission: ObserverPermission::ObserverOnly,
            cert_der: vec![1, 2, 3],
            mac_address: [0, 1, 2, 3, 4, 5],
            learned_interface: "en0".to_string(),
            http_port: 47989,
            https_port: 47984,
            broadcast_address: Ipv4Addr::new(192, 168, 1, 255),
            secure_on: Some(secure_on),
            last_state: HostState::Unknown,
            last_observed_at: None,
            enrolled_at: OffsetDateTime::now_utc(),
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn reenrollment_preserves_id_and_reseals_secure_on_for_that_id() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("beacon.db")).unwrap();
        let master_key = MasterKey([7; 32]);
        let first_id = Uuid::new_v4();

        let persisted =
            upsert_by_gamestream_uuid(&db, &master_key, &test_host(first_id, [1, 2, 3, 4, 5, 6]))
                .await
                .unwrap();
        assert_eq!(persisted, first_id);

        let persisted_again = upsert_by_gamestream_uuid(
            &db,
            &master_key,
            &test_host(Uuid::new_v4(), [6, 5, 4, 3, 2, 1]),
        )
        .await
        .unwrap();
        assert_eq!(persisted_again, first_id);

        let restored = get(&db, &master_key, first_id).await.unwrap().unwrap();
        assert_eq!(restored.secure_on, Some([6, 5, 4, 3, 2, 1]));
    }
}

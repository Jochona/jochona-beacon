//! The master key protecting encrypted-at-rest secrets (private keys,
//! SecureOn passwords). Resolved, in order:
//!
//! 1. A systemd credential named `master-key`, delivered via
//!    `$CREDENTIALS_DIRECTORY/master-key` (32 raw bytes). The packaged unit
//!    (`packaging/systemd/jochona-beacon.service`) wires this up with
//!    `LoadCredential=master-key:/etc/jochona-beacon/master-key`, where the
//!    source file on disk is root-owned, mode 0600 — systemd itself reads
//!    it as root at unit start and re-exposes it only to this service's
//!    unprivileged user via a private tmpfs.
//! 2. A local fallback file `<data_dir>/master.key`, generated on first use
//!    and enforced to mode 0600. Used for non-systemd installs (tarball,
//!    development). We fail closed rather than trust a file whose
//!    permissions have been loosened by someone else.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MASTER_KEY_LEN: usize = 32;
const SYSTEMD_CREDENTIAL_NAME: &str = "master-key";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; MASTER_KEY_LEN]);

impl MasterKey {
    pub fn load(data_dir: &Path) -> Result<Self> {
        if let Some(key) = Self::from_systemd_credential()? {
            tracing::info!(source = "systemd-credential", "loaded master key");
            return Ok(key);
        }
        tracing::warn!(
            source = "local-fallback-file",
            "no systemd credential found; using root/service-owned 0600 fallback key file"
        );
        Self::from_fallback_file(&data_dir.join("master.key"))
    }

    fn from_systemd_credential() -> Result<Option<Self>> {
        let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
            return Ok(None);
        };
        let path = PathBuf::from(dir).join(SYSTEMD_CREDENTIAL_NAME);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading systemd credential {}", path.display()))?;
        if bytes.len() != MASTER_KEY_LEN {
            bail!(
                "systemd credential {} must be exactly {MASTER_KEY_LEN} bytes, got {}",
                path.display(),
                bytes.len()
            );
        }
        let mut key = [0u8; MASTER_KEY_LEN];
        key.copy_from_slice(&bytes);
        Ok(Some(Self(key)))
    }

    fn from_fallback_file(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        if path.exists() {
            verify_fallback_permissions(path)?;
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading fallback master key {}", path.display()))?;
            if bytes.len() != MASTER_KEY_LEN {
                bail!(
                    "fallback master key {} must be exactly {MASTER_KEY_LEN} bytes, got {} \
                     (delete it to regenerate, but every encrypted secret becomes unrecoverable)",
                    path.display(),
                    bytes.len()
                );
            }
            let mut key = [0u8; MASTER_KEY_LEN];
            key.copy_from_slice(&bytes);
            return Ok(Self(key));
        }

        let mut key = [0u8; MASTER_KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        write_fallback_atomically(path, &key)?;
        Ok(Self(key))
    }
}

#[cfg(unix)]
fn verify_fallback_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!(
            "refusing to use master key {}: expected mode 0600, found {:o}. Fix with `chmod 600 {}`.",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_fallback_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_fallback_atomically(path: &Path, key: &[u8; MASTER_KEY_LEN]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let tmp_path = path.with_extension("key.tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        file.write_all(key)?;
        file.sync_all()?;
    }
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("installing fallback master key at {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_fallback_atomically(path: &Path, key: &[u8; MASTER_KEY_LEN]) -> Result<()> {
    std::fs::write(path, key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_reloads_fallback_key_with_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        let first = MasterKey::from_fallback_file(&path).unwrap();
        let second = MasterKey::from_fallback_file(&path).unwrap();
        assert_eq!(first.0, second.0, "fallback key must persist across loads");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_loosened_fallback_key_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        std::fs::write(&path, [7u8; MASTER_KEY_LEN]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let result = MasterKey::from_fallback_file(&path);
        assert!(result.is_err(), "0644 fallback key must be rejected");
    }
}

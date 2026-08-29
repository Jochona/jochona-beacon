//! SQLite-backed storage. One `rusqlite::Connection` behind a `Mutex`,
//! driven through `spawn_blocking` — Beacon's write volume (pairing,
//! enrollment, wake, and periodic observation) never approaches a scale
//! where a connection pool would pay for its own complexity.

pub mod migrations;
pub mod repo;
pub mod secret_box;

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::Connection;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Opens (creating if absent) the SQLite database at `path`, applies
    /// pragmas, and runs every pending migration inside one transaction.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating database directory {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite database at {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrations::run(&conn)?;
        harden_file_permissions(path)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrations::run(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Runs `f` against the connection on a blocking-safe thread and
    /// returns its result. Every repository method is built on this.
    pub async fn call<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Connection) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().expect("sqlite connection mutex poisoned");
            f(&guard)
        })
        .await
        .context("sqlite worker task panicked")?
    }

    /// Synchronous escape hatch for call sites that are already off the
    /// async runtime (CLI bootstrap, migration checks).
    pub fn call_blocking<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Connection) -> Result<R>,
    {
        let guard = self.conn.lock().expect("sqlite connection mutex poisoned");
        f(&guard)
    }
}

#[cfg(unix)]
fn harden_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for candidate in [
        path.to_path_buf(),
        append_suffix(path, "-wal"),
        append_suffix(path, "-shm"),
    ] {
        if candidate.exists() {
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", candidate.display()))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn append_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    std::path::PathBuf::from(s)
}

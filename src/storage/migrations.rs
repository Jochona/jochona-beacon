//! Forward-only SQL migrations, tracked via SQLite's built-in
//! `PRAGMA user_version` so there is no extra bookkeeping table to get out
//! of sync with reality.

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Ordered list of (version, sql). Version `N` is applied when
/// `user_version < N`; each script must be idempotent-safe to re-run only
/// in the sense that it is never re-run once its version has been recorded.
const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../../migrations/0001_init.sql"))];

pub fn run(conn: &Connection) -> Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    for (version, sql) in MIGRATIONS {
        if *version <= current {
            continue;
        }
        conn.execute_batch(sql)
            .with_context(|| format!("applying migration {version}"))?;
        conn.pragma_update(None, "user_version", version)
            .with_context(|| format!("recording migration {version}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_apply_cleanly_and_are_idempotent_on_reopen() {
        let conn = Connection::open_in_memory().unwrap();
        run(&conn).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 1);
        // Re-running against the same connection must not error or re-apply.
        run(&conn).unwrap();
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hosts'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 1);
    }
}

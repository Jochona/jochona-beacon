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
    apply(conn, MIGRATIONS)
}

/// Applies every not-yet-recorded migration, each inside its own explicit
/// transaction (`migrations/0001_init.sql`'s own header comment promises
/// this): a script that fails partway rolls back completely, including
/// `user_version`, so a retry after fixing the underlying problem starts
/// from a clean slate instead of hitting "table already exists" against
/// whatever the failed attempt partially created.
fn apply(conn: &Connection, migrations: &[(i64, &str)]) -> Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    for (version, sql) in migrations {
        if *version <= current {
            continue;
        }
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(sql)
            .with_context(|| format!("applying migration {version}"))?;
        tx.pragma_update(None, "user_version", version)
            .with_context(|| format!("recording migration {version}"))?;
        tx.commit()
            .with_context(|| format!("committing migration {version}"))?;
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

    #[test]
    fn a_failing_migration_rolls_back_atomically_and_never_advances_user_version() {
        let conn = Connection::open_in_memory().unwrap();
        // A syntactically valid first statement followed by a broken one:
        // proves the whole script — including the table the first
        // statement created — rolls back together, not just the failing
        // statement.
        let migrations: &[(i64, &str)] =
            &[(1, "CREATE TABLE t (id INTEGER PRIMARY KEY); NOT VALID SQL;")];

        let result = apply(&conn, migrations);
        assert!(
            result.is_err(),
            "a broken migration script must surface an error"
        );

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            version, 0,
            "a failed migration must never advance user_version"
        );

        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='t'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            tables, 0,
            "every partial DDL change from the failed script must be rolled back"
        );
    }
}

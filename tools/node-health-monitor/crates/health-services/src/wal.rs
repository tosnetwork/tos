//! Reclaim a WAL without waiting for readers; callers hold the writer connection.
use rusqlite::Connection;
use std::time::Duration;

pub(crate) fn try_truncate(conn: &Connection) -> rusqlite::Result<(i64, i64, i64)> {
    // TRUNCATE needs a reader-free reset. A zero busy timeout makes a pinned
    // reader an immediate refusal, rather than spending the writer timeout.
    let timeout: u64 = conn.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    conn.busy_timeout(Duration::ZERO)?;
    let result = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    });
    conn.busy_timeout(Duration::from_millis(timeout))?;
    result
}

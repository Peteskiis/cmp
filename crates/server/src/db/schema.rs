use tokio_rusqlite::Connection;

const CURRENT_VERSION: u32 = 3;

/// Initialize the database schema, pragmas, and migrations.
pub async fn initialize(conn: &Connection) -> anyhow::Result<()> {
    conn.call(|conn| {
        // Enable foreign key enforcement (SQLite ignores REFERENCES without this)
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // WAL mode for concurrent read/write from multiple async tasks
        conn.pragma_update(None, "journal_mode", "WAL")?;

        let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

        if version < 1 {
            // Wrap migration in a transaction — partial failure must not leave a broken schema
            let tx = conn.transaction()?;
            tx.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS users (
                    user_id     TEXT PRIMARY KEY,
                    identity_key BLOB NOT NULL,
                    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS signed_prekeys (
                    user_id     TEXT NOT NULL REFERENCES users(user_id),
                    key_id      INTEGER NOT NULL,
                    public_key  BLOB NOT NULL,
                    signature   BLOB NOT NULL,
                    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (user_id, key_id)
                );

                CREATE TABLE IF NOT EXISTS prekeys (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     TEXT NOT NULL REFERENCES users(user_id),
                    key_id      INTEGER NOT NULL,
                    public_key  BLOB NOT NULL,
                    UNIQUE(user_id, key_id)
                );
                CREATE INDEX IF NOT EXISTS idx_prekeys_user ON prekeys(user_id);

                CREATE TABLE IF NOT EXISTS message_queue (
                    message_id   TEXT PRIMARY KEY,
                    recipient_id TEXT NOT NULL REFERENCES users(user_id),
                    sender_id    TEXT NOT NULL,
                    envelope     TEXT NOT NULL,
                    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_queue_recipient
                    ON message_queue(recipient_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_queue_created
                    ON message_queue(created_at);

                ",
            )?;
            tx.pragma_update(None, "user_version", 1)?;
            tx.commit()?;
        }

        if version < 2 {
            migrate_v2(conn)?;
        }

        if version < 3 {
            migrate_v3(conn)?;
        }

        Ok(())
    })
    .await?;

    Ok(())
}

fn migrate_v2(conn: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS read_receipt_queue (
            receipt_id  TEXT PRIMARY KEY,
            recipient_id TEXT NOT NULL REFERENCES users(user_id),
            sender_id   TEXT NOT NULL,
            envelope    TEXT NOT NULL,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_receipts_recipient
            ON read_receipt_queue(recipient_id, created_at);",
    )?;
    tx.pragma_update(None, "user_version", 2)?;
    tx.commit()
}

fn migrate_v3(conn: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS prekey_fetch_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_prekey_fetch_requester
            ON prekey_fetch_events(requester_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_prekey_fetch_target
            ON prekey_fetch_events(target_id, created_at);",
    )?;
    tx.pragma_update(None, "user_version", CURRENT_VERSION)?;
    tx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn version_two_database_runs_version_three_migration() {
        let conn = Connection::open_in_memory().await.unwrap();
        conn.call(|conn| {
            conn.pragma_update(None, "user_version", 2)?;
            Ok(())
        })
        .await
        .unwrap();

        initialize(&conn).await.unwrap();

        conn.call(|conn| {
            let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
            let table_exists: bool = conn.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'prekey_fetch_events'
                )",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(version, CURRENT_VERSION);
            assert!(table_exists);
            Ok(())
        })
        .await
        .unwrap();
    }
}

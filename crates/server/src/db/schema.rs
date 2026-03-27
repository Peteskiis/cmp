use tokio_rusqlite::Connection;

const CURRENT_VERSION: u32 = 1;

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
            tx.pragma_update(None, "user_version", CURRENT_VERSION)?;
            tx.commit()?;
        }

        Ok(())
    })
    .await?;

    Ok(())
}

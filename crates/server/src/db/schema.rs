use tokio_rusqlite::Connection;

const CURRENT_VERSION: u32 = 7;

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

        if version < 4 {
            migrate_v4(conn)?;
        }

        if version < 5 {
            migrate_v5(conn)?;
        }

        if version < 6 {
            migrate_v6(conn)?;
        }
        if version < 7 {
            migrate_v7(conn)?;
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
    tx.pragma_update(None, "user_version", 3)?;
    tx.commit()
}

fn migrate_v4(conn: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS prekey_inventory (
            user_id TEXT PRIMARY KEY REFERENCES users(user_id),
            high_water INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO prekey_inventory (user_id, high_water)
        SELECT users.user_id, COALESCE(MAX(prekeys.key_id), -1)
        FROM users LEFT JOIN prekeys ON prekeys.user_id = users.user_id
        GROUP BY users.user_id;",
    )?;
    tx.pragma_update(None, "user_version", 4)?;
    tx.commit()
}

fn migrate_v5(conn: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        "ALTER TABLE prekeys ADD COLUMN created_at INTEGER;
         UPDATE prekeys SET created_at = unixepoch() WHERE created_at IS NULL;",
    )?;
    tx.pragma_update(None, "user_version", 5)?;
    tx.commit()
}

fn migrate_v6(conn: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    const LEGACY_HIGH_WATER: i64 = (1_i64 << 31) - 1;
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE prekey_inventory SET high_water = MAX(high_water, ?1)",
        [LEGACY_HIGH_WATER],
    )?;
    tx.pragma_update(None, "user_version", 6)?;
    tx.commit()
}

fn migrate_v7(conn: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TABLE prekey_reservations (
            requester_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            key_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (requester_id, target_id, key_id)
        );
        CREATE INDEX idx_prekey_reservation_expiry
            ON prekey_reservations(expires_at);",
    )?;
    tx.pragma_update(None, "user_version", CURRENT_VERSION)?;
    tx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn older_database_runs_all_later_migrations() {
        let conn = Connection::open_in_memory().await.unwrap();
        initialize(&conn).await.unwrap();
        conn.call(|conn| {
            conn.execute_batch(
                "DROP TABLE prekey_fetch_events;
                 DROP TABLE prekey_inventory;
                 DROP TABLE prekey_reservations;
                 ALTER TABLE prekeys DROP COLUMN created_at;",
            )?;
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
            let inventory_exists: bool = conn.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'prekey_inventory'
                )",
                [],
                |row| row.get(0),
            )?;
            assert!(inventory_exists);
            Ok(())
        })
        .await
        .unwrap();
    }
}

use std::path::Path;

use rusqlite::{Connection, params};

const CURRENT_VERSION: u32 = 2;
const HISTORY_LOAD_LIMIT: i64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MessageDirection {
    Sent = 0,
    Received = 1,
}

pub(crate) struct StoredMessage {
    pub(crate) peer_id: String,
    pub(crate) direction: MessageDirection,
    pub(crate) body: String,
}

impl From<StoredMessage> for crate::app::ChatEntry {
    fn from(msg: StoredMessage) -> Self {
        match msg.direction {
            MessageDirection::Sent => Self::Sent(msg.body),
            MessageDirection::Received => Self::Received {
                sender: msg.peer_id,
                text: msg.body,
            },
        }
    }
}

/// Open (or create) the client database with WAL mode and schema migrations.
/// Sets `0o600` file permissions on Unix to protect plaintext messages.
pub(crate) fn open(path: &Path) -> anyhow::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        // Restrict parent directory — protects DB, WAL, and SHM files in one shot
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;

    let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if version < 1 {
        let tx = conn.transaction()?;
        tx.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id     TEXT NOT NULL,
                direction   INTEGER NOT NULL CHECK (direction IN (0, 1)),
                message_id  TEXT,
                body        TEXT NOT NULL,
                created_at  INTEGER NOT NULL DEFAULT (unixepoch())
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_msgid
                ON messages(message_id) WHERE message_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_messages_peer
                ON messages(peer_id, id);
            ",
        )?;
        tx.pragma_update(None, "user_version", 1)?;
        tx.commit()?;
    }

    if version < 2 {
        let tx = conn.transaction()?;
        tx.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS peer_identity_keys (
                peer_id       TEXT PRIMARY KEY,
                identity_key  TEXT NOT NULL,
                first_seen    INTEGER NOT NULL DEFAULT (unixepoch())
            );
            CREATE TABLE IF NOT EXISTS verified_contacts (
                peer_id       TEXT PRIMARY KEY,
                fingerprint   TEXT NOT NULL,
                verified_at   INTEGER NOT NULL DEFAULT (unixepoch())
            );
            ",
        )?;
        tx.pragma_update(None, "user_version", CURRENT_VERSION)?;
        tx.commit()?;
    }

    Ok(conn)
}

/// Persist a message. Uses `INSERT OR IGNORE` to deduplicate on `message_id`.
pub(crate) fn insert_message(
    conn: &Connection,
    peer_id: &str,
    direction: MessageDirection,
    message_id: &str,
    body: &str,
) -> anyhow::Result<bool> {
    let changed = conn.execute(
        "INSERT OR IGNORE INTO messages (peer_id, direction, message_id, body)
         VALUES (?1, ?2, ?3, ?4)",
        params![peer_id, direction as u8, message_id, body],
    )?;
    Ok(changed > 0)
}

/// Result of storing a peer's identity key — indicates whether it changed.
#[allow(dead_code)] // `Changed::old_key` reserved for future identity-change UI
pub(crate) enum IdentityKeyStatus {
    /// First time seeing this peer's key.
    New,
    /// Key matches the stored value.
    Unchanged,
    /// Key differs from the stored value.
    Changed { old_key: String },
}

/// Store a peer's identity key. Returns the status indicating whether this is
/// new, unchanged, or changed compared to a previously stored key.
pub(crate) fn store_peer_identity_key(
    conn: &Connection,
    peer_id: &str,
    identity_key_b64: &str,
) -> anyhow::Result<IdentityKeyStatus> {
    // Atomic: key update + verification removal must not be split.
    // unchecked_transaction because conn is &Connection (shared ref); safe
    // because the client event loop is single-threaded.
    let tx = conn.unchecked_transaction()?;

    let existing: Option<String> = tx
        .query_row(
            "SELECT identity_key FROM peer_identity_keys WHERE peer_id = ?1",
            params![peer_id],
            |row| row.get(0),
        )
        .ok();

    let status = match existing {
        Some(ref stored) if stored == identity_key_b64 => IdentityKeyStatus::Unchanged,
        Some(old_key) => {
            tx.execute(
                "UPDATE peer_identity_keys SET identity_key = ?2, first_seen = unixepoch()
                 WHERE peer_id = ?1",
                params![peer_id, identity_key_b64],
            )?;
            tx.execute(
                "DELETE FROM verified_contacts WHERE peer_id = ?1",
                params![peer_id],
            )?;
            IdentityKeyStatus::Changed { old_key }
        }
        None => {
            tx.execute(
                "INSERT INTO peer_identity_keys (peer_id, identity_key) VALUES (?1, ?2)",
                params![peer_id, identity_key_b64],
            )?;
            IdentityKeyStatus::New
        }
    };

    tx.commit()?;
    Ok(status)
}

/// Get the stored identity key for a peer.
pub(crate) fn get_peer_identity_key(conn: &Connection, peer_id: &str) -> Option<String> {
    conn.query_row(
        "SELECT identity_key FROM peer_identity_keys WHERE peer_id = ?1",
        params![peer_id],
        |row| row.get(0),
    )
    .ok()
}

/// Store (or update) a verification record for a peer.
pub(crate) fn store_verification(
    conn: &Connection,
    peer_id: &str,
    fingerprint: &str,
) -> anyhow::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO verified_contacts (peer_id, fingerprint) VALUES (?1, ?2)",
        params![peer_id, fingerprint],
    )?;
    Ok(())
}

/// Get the verification record for a peer, if any.
pub(crate) fn get_verification(conn: &Connection, peer_id: &str) -> Option<String> {
    conn.query_row(
        "SELECT fingerprint FROM verified_contacts WHERE peer_id = ?1",
        params![peer_id],
        |row| row.get(0),
    )
    .ok()
}

/// Remove verification for a peer (called when their identity key changes).
pub(crate) fn remove_verification(conn: &Connection, peer_id: &str) -> anyhow::Result<()> {
    conn.execute(
        "DELETE FROM verified_contacts WHERE peer_id = ?1",
        params![peer_id],
    )?;
    Ok(())
}

/// Load the most recent messages for a peer, returned in ascending order (oldest first).
pub(crate) fn load_recent_messages(
    conn: &Connection,
    peer_id: &str,
) -> anyhow::Result<Vec<StoredMessage>> {
    let mut stmt = conn.prepare(
        "SELECT peer_id, direction, body FROM messages
         WHERE peer_id = ?1
         ORDER BY id DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![peer_id, HISTORY_LOAD_LIMIT], |row| {
        let dir: u8 = row.get(1)?;
        let direction = match dir {
            0 => MessageDirection::Sent,
            1 => MessageDirection::Received,
            other => {
                return Err(rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Integer,
                    format!("invalid direction: {other}").into(),
                ));
            }
        };
        Ok(StoredMessage {
            peer_id: row.get(0)?,
            direction,
            body: row.get(2)?,
        })
    })?;
    let mut messages: Vec<StoredMessage> = rows.collect::<Result<_, _>>()?;
    messages.reverse(); // DESC → ASC for display order
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp_db() -> (Connection, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = open(&path).unwrap();
        (conn, dir)
    }

    #[test]
    fn insert_and_load_roundtrip() {
        let (conn, _dir) = open_temp_db();
        insert_message(&conn, "alice", MessageDirection::Sent, "m1", "hello").unwrap();
        insert_message(&conn, "alice", MessageDirection::Received, "m2", "hi back").unwrap();

        let msgs = load_recent_messages(&conn, "alice").unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].direction, MessageDirection::Sent);
        assert_eq!(msgs[0].body, "hello");
        assert_eq!(msgs[1].direction, MessageDirection::Received);
        assert_eq!(msgs[1].body, "hi back");
    }

    #[test]
    fn dedup_on_message_id() {
        let (conn, _dir) = open_temp_db();
        insert_message(&conn, "bob", MessageDirection::Received, "dup", "msg").unwrap();
        insert_message(&conn, "bob", MessageDirection::Received, "dup", "msg").unwrap();

        let msgs = load_recent_messages(&conn, "bob").unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn load_respects_limit_and_ordering() {
        let (conn, _dir) = open_temp_db();
        for i in 0..150 {
            insert_message(
                &conn,
                "carol",
                MessageDirection::Sent,
                &format!("m{i}"),
                &format!("msg {i}"),
            )
            .unwrap();
        }

        let msgs = load_recent_messages(&conn, "carol").unwrap();
        assert_eq!(msgs.len(), 100);
        // First message should be #50 (most recent 100 of 150, ascending)
        assert_eq!(msgs[0].body, "msg 50");
        assert_eq!(msgs[99].body, "msg 149");
    }

    #[test]
    fn load_empty_peer() {
        let (conn, _dir) = open_temp_db();
        let msgs = load_recent_messages(&conn, "nobody").unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn different_peers_isolated() {
        let (conn, _dir) = open_temp_db();
        insert_message(&conn, "alice", MessageDirection::Sent, "a1", "to alice").unwrap();
        insert_message(&conn, "bob", MessageDirection::Sent, "b1", "to bob").unwrap();

        let alice_msgs = load_recent_messages(&conn, "alice").unwrap();
        let bob_msgs = load_recent_messages(&conn, "bob").unwrap();
        assert_eq!(alice_msgs.len(), 1);
        assert_eq!(bob_msgs.len(), 1);
        assert_eq!(alice_msgs[0].body, "to alice");
        assert_eq!(bob_msgs[0].body, "to bob");
    }

    #[test]
    fn multiline_body_preserved() {
        let (conn, _dir) = open_temp_db();
        let body = "line 1\nline 2\nline 3";
        insert_message(&conn, "alice", MessageDirection::Sent, "ml", body).unwrap();

        let msgs = load_recent_messages(&conn, "alice").unwrap();
        assert_eq!(msgs[0].body, body);
    }

    #[test]
    fn reopen_existing_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = open(&path).unwrap();
        insert_message(&conn, "alice", MessageDirection::Sent, "r1", "persisted").unwrap();
        drop(conn);

        let conn2 = open(&path).unwrap();
        let msgs = load_recent_messages(&conn2, "alice").unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "persisted");
    }

    #[test]
    fn stored_message_to_chat_entry() {
        let sent = StoredMessage {
            peer_id: "bob".into(),
            direction: MessageDirection::Sent,
            body: "hello".into(),
        };
        let entry: crate::app::ChatEntry = sent.into();
        assert!(matches!(entry, crate::app::ChatEntry::Sent(t) if t == "hello"));

        let recv = StoredMessage {
            peer_id: "bob".into(),
            direction: MessageDirection::Received,
            body: "hi".into(),
        };
        let entry: crate::app::ChatEntry = recv.into();
        assert!(
            matches!(entry, crate::app::ChatEntry::Received { sender, text } if sender == "bob" && text == "hi")
        );
    }
}

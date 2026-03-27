use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use protocol::ServerMessage;
use tokio::sync::mpsc;

/// Unique connection identifier, monotonically increasing.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

struct ConnEntry {
    conn_id: u64,
    sender: mpsc::Sender<ServerMessage>,
}

/// Tracks online users and their message channels.
///
/// # Deadlock safety
///
/// Never iterate the map while holding a `Ref` guard from a `get()` call.
/// Use `insert`/`remove`/`get` only — these acquire per-shard locks that don't conflict.
pub struct ConnectionRegistry {
    online: DashMap<String, ConnEntry>,
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self {
            online: DashMap::new(),
        }
    }

    /// Register a connected user. Returns the connection ID.
    /// If the user was already online, sends a "session replaced" error
    /// to the old connection before replacing it.
    pub fn insert(&self, user_id: String, sender: mpsc::Sender<ServerMessage>) -> u64 {
        let conn_id = next_conn_id();

        if let Some(old) = self.online.insert(user_id, ConnEntry { conn_id, sender }) {
            // Notify the displaced connection so it knows to stop
            let _ = old.sender.try_send(ServerMessage::Error {
                code: 409,
                message: "session replaced by new connection".to_owned(),
            });
        }

        conn_id
    }

    /// Remove a user from the registry, but ONLY if the stored connection
    /// matches the given `conn_id`. Prevents a closing old connection from
    /// evicting a newer one.
    pub fn remove_if_match(&self, user_id: &str, conn_id: u64) {
        self.online
            .remove_if(user_id, |_, entry| entry.conn_id == conn_id);
    }

    /// Send a message to an online user. Returns false if offline, channel closed,
    /// or channel full (backpressure on slow clients).
    pub fn send_to(&self, user_id: &str, msg: ServerMessage) -> bool {
        if let Some(entry) = self.online.get(user_id) {
            entry.sender.try_send(msg).is_ok()
        } else {
            false
        }
    }
}

use std::fs::{self, File};
#[cfg(test)]
use std::io;
use std::io::Write;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
#[cfg(test)]
use tempfile::NamedTempFile;

pub(crate) struct CryptoStore {
    connection: Connection,
}

impl CryptoStore {
    pub(crate) fn open(path: &Path) -> anyhow::Result<Self> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS core_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbox (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS processed_messages (
                peer_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                pending_plaintext TEXT,
                processed_at INTEGER NOT NULL,
                PRIMARY KEY (peer_id, message_id)
            );",
        )?;
        Ok(Self { connection })
    }

    pub(crate) fn load_core<T: DeserializeOwned + Default>(&self) -> anyhow::Result<T> {
        let json: Option<String> = self
            .connection
            .query_row("SELECT json FROM core_state WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        json.map_or_else(|| Ok(T::default()), |json| Ok(serde_json::from_str(&json)?))
    }

    pub(crate) fn load_outbox<T: DeserializeOwned>(&self) -> anyhow::Result<Vec<T>> {
        let mut statement = self
            .connection
            .prepare("SELECT payload FROM outbox ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    pub(crate) fn load_processed(&self) -> anyhow::Result<Vec<ProcessedRow>> {
        let mut statement = self.connection.prepare(
            "SELECT peer_id, message_id, pending_plaintext, processed_at
             FROM processed_messages",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(ProcessedRow {
                peer_id: row.get(0)?,
                message_id: row.get(1)?,
                pending_plaintext: row.get(2)?,
                processed_at: row.get(3)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub(crate) fn save_core<T: Serialize>(&self, core: &T) -> anyhow::Result<()> {
        let json = serde_json::to_string(core)?;
        self.connection.execute(
            "INSERT INTO core_state (id, json) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            [json],
        )?;
        Ok(())
    }

    pub(crate) fn save_core_and_enqueue<T: Serialize, U: Serialize>(
        &self,
        core: &T,
        correlation_id: &str,
        outbound: &U,
    ) -> anyhow::Result<()> {
        let core = serde_json::to_string(core)?;
        let outbound = serde_json::to_string(outbound)?;
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO core_state (id, json) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            [core],
        )?;
        transaction.execute(
            "INSERT INTO outbox (correlation_id, payload) VALUES (?1, ?2)",
            params![correlation_id, outbound],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn save_core_and_processed<T: Serialize>(
        &self,
        core: &T,
        row: &ProcessedRow,
    ) -> anyhow::Result<()> {
        let core = serde_json::to_string(core)?;
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO core_state (id, json) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            [core],
        )?;
        transaction.execute(
            "INSERT INTO processed_messages
                (peer_id, message_id, pending_plaintext, processed_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                row.peer_id,
                row.message_id,
                row.pending_plaintext,
                row.processed_at
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn mark_processed_committed(
        &self,
        peer_id: &str,
        message_id: &str,
    ) -> anyhow::Result<()> {
        self.connection.execute(
            "UPDATE processed_messages SET pending_plaintext = NULL
             WHERE peer_id = ?1 AND message_id = ?2",
            params![peer_id, message_id],
        )?;
        Ok(())
    }

    pub(crate) fn delete_outbound(&self, correlation_id: &str) -> anyhow::Result<()> {
        self.connection.execute(
            "DELETE FROM outbox WHERE correlation_id = ?1",
            [correlation_id],
        )?;
        Ok(())
    }

    pub(crate) fn save_core_and_delete_outbound<T: Serialize>(
        &self,
        core: &T,
        correlation_id: &str,
    ) -> anyhow::Result<()> {
        let core = serde_json::to_string(core)?;
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO core_state (id, json) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            [core],
        )?;
        transaction.execute(
            "DELETE FROM outbox WHERE correlation_id = ?1",
            [correlation_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn save_core_and_delete_outbound_batch<T: Serialize>(
        &self,
        core: &T,
        correlation_ids: &[String],
    ) -> anyhow::Result<()> {
        let core = serde_json::to_string(core)?;
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO core_state (id, json) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            [core],
        )?;
        let mut statement = transaction.prepare("DELETE FROM outbox WHERE correlation_id = ?1")?;
        for correlation_id in correlation_ids {
            statement.execute([correlation_id])?;
        }
        drop(statement);
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn confirm_ack(&self, ack_id: &str, message_ids: &[String]) -> anyhow::Result<()> {
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute("DELETE FROM outbox WHERE correlation_id = ?1", [ack_id])?;
        let mut statement =
            transaction.prepare("DELETE FROM processed_messages WHERE message_id = ?1")?;
        for message_id in message_ids {
            statement.execute([message_id])?;
        }
        drop(statement);
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn prune_processed(&self, cutoff: u64) -> anyhow::Result<()> {
        self.connection.execute(
            "DELETE FROM processed_messages WHERE processed_at < ?1",
            [cutoff],
        )?;
        Ok(())
    }
}

pub(crate) struct ProcessedRow {
    pub(crate) peer_id: String,
    pub(crate) message_id: String,
    pub(crate) pending_plaintext: Option<String>,
    pub(crate) processed_at: u64,
}

/// Write a new file durably, failing if the destination already exists.
pub(crate) fn write_new(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    sync_parent(path)?;
    Ok(())
}

#[cfg(test)]
fn replace_file(
    path: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("state path has no parent"))?;
    let mut temporary = NamedTempFile::new_in(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    write(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_parent(path)?;
    Ok(())
}

fn sync_parent(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("state path has no parent"))?;
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_write_keeps_previous_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        fs::write(&path, b"previous").unwrap();

        let result = replace_file(&path, |file| {
            file.write_all(b"part")?;
            Err(io::Error::other("injected partial write"))
        });

        assert!(result.is_err());
        assert_eq!(fs::read(path).unwrap(), b"previous");
    }
}

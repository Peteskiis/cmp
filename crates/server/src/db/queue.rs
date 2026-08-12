use tokio_rusqlite::Connection;

/// Enqueue an encrypted message for delivery.
///
/// Deduplicates on `message_id`. Checks per-user queue depth before inserting.
/// Accepts owned `envelope_json` to avoid cloning ~512KB on the hot path.
pub async fn enqueue(
    conn: &Connection,
    message_id: &str,
    recipient_id: &str,
    sender_id: &str,
    envelope_json: String,
    max_queue_per_user: usize,
) -> anyhow::Result<EnqueueResult> {
    let message_id = message_id.to_owned();
    let recipient_id = recipient_id.to_owned();
    let sender_id = sender_id.to_owned();

    conn.call(move |conn| {
        // Wrap in transaction to prevent TOCTOU between COUNT and INSERT
        let tx = conn.transaction()?;

        // Check recipient exists (clear result vs FK constraint error)
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = ?1)",
            [&recipient_id],
            |row| row.get(0),
        )?;
        if !exists {
            tx.rollback()?;
            return Ok(EnqueueResult::RecipientNotFound);
        }

        // Check per-user queue depth
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM message_queue WHERE recipient_id = ?1",
            [&recipient_id],
            |row| row.get(0),
        )?;
        // count is non-negative from COUNT(*); MAX_QUEUE_PER_USER (10,000) fits in i64
        if count >= i64::try_from(max_queue_per_user).unwrap_or(i64::MAX) {
            tx.rollback()?;
            return Ok(EnqueueResult::QueueFull);
        }

        let changed = tx.execute(
            "INSERT OR IGNORE INTO message_queue (message_id, recipient_id, sender_id, envelope)
             VALUES (?1, ?2, ?3, ?4)",
            (&message_id, &recipient_id, &sender_id, &envelope_json),
        )?;
        tx.commit()?;

        if changed > 0 {
            Ok(EnqueueResult::Inserted)
        } else {
            Ok(EnqueueResult::Duplicate)
        }
    })
    .await
    .map_err(Into::into)
}

/// Result of attempting to enqueue a message.
#[non_exhaustive]
pub enum EnqueueResult {
    Inserted,
    Duplicate,
    QueueFull,
    RecipientNotFound,
}

/// Retrieve the next queued message after `after_row_id`.
///
/// Fetching one row at a time prevents a batch of maximum-size ciphertexts
/// from being materialized in memory before byte-bounded pages are assembled.
pub async fn get_next_pending(
    conn: &Connection,
    recipient_id: &str,
    after_row_id: i64,
) -> anyhow::Result<Option<QueuedRow>> {
    let recipient_id = recipient_id.to_owned();

    conn.call(move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT rowid, message_id, sender_id, envelope, created_at
             FROM message_queue
             WHERE recipient_id = ?1 AND rowid > ?2
             ORDER BY rowid ASC
             LIMIT 1",
        )?;
        let mut rows = stmt.query((&recipient_id, after_row_id))?;
        rows.next()?
            .map(|row| {
                Ok(QueuedRow {
                    row_id: row.get(0)?,
                    message_id: row.get(1)?,
                    sender_id: row.get(2)?,
                    envelope_json: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .transpose()
    })
    .await
    .map_err(Into::into)
}

/// Delete acknowledged messages by their IDs, scoped to the given recipient.
/// Only the intended recipient can ack their own messages.
pub async fn delete_messages(
    conn: &Connection,
    recipient_id: &str,
    message_ids: &[String],
) -> anyhow::Result<u64> {
    let recipient_id = recipient_id.to_owned();
    let message_ids = message_ids.to_vec();

    conn.call(move |conn| {
        let tx = conn.transaction()?;
        let mut deleted = 0u64;
        {
            let mut stmt = tx
                .prepare("DELETE FROM message_queue WHERE message_id = ?1 AND recipient_id = ?2")?;
            for id in &message_ids {
                // usize rows changed fits in u64 on all platforms
                #[allow(clippy::cast_possible_truncation)]
                {
                    deleted += stmt.execute(rusqlite::params![id, &recipient_id])? as u64;
                }
            }
        }
        tx.commit()?;
        Ok(deleted)
    })
    .await
    .map_err(Into::into)
}

/// Delete messages older than `max_age_days` days. Returns count deleted.
pub async fn gc_old_messages(conn: &Connection, max_age_days: u32) -> anyhow::Result<u64> {
    conn.call(move |conn| {
        let deleted = conn.execute(
            "DELETE FROM message_queue WHERE created_at < datetime('now', ?1)",
            [format!("-{max_age_days} days")],
        )?;
        // usize fits in u64 on all platforms
        #[allow(clippy::cast_possible_truncation)]
        Ok(deleted as u64)
    })
    .await
    .map_err(Into::into)
}

pub struct QueuedRow {
    pub row_id: i64,
    pub message_id: String,
    pub sender_id: String,
    pub envelope_json: String,
    pub created_at: String,
}

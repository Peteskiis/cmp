use tokio_rusqlite::Connection;

/// Enqueue an encrypted message for delivery. Deduplicates on `message_id`.
/// Accepts owned `envelope_json` to avoid cloning the largest allocation (~512KB) on the hot path.
pub async fn enqueue(
    conn: &Connection,
    message_id: &str,
    recipient_id: &str,
    sender_id: &str,
    envelope_json: String,
) -> anyhow::Result<bool> {
    let message_id = message_id.to_owned();
    let recipient_id = recipient_id.to_owned();
    let sender_id = sender_id.to_owned();

    conn.call(move |conn| {
        let changed = conn.execute(
            "INSERT OR IGNORE INTO message_queue (message_id, recipient_id, sender_id, envelope)
             VALUES (?1, ?2, ?3, ?4)",
            (&message_id, &recipient_id, &sender_id, &envelope_json),
        )?;
        Ok(changed > 0)
    })
    .await
    .map_err(Into::into)
}

/// Retrieve queued messages for a recipient, ordered by creation time.
/// Limited to `max_count` to prevent unbounded memory use.
pub async fn get_pending(
    conn: &Connection,
    recipient_id: &str,
    max_count: usize,
) -> anyhow::Result<Vec<QueuedRow>> {
    let recipient_id = recipient_id.to_owned();

    conn.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT message_id, sender_id, envelope
             FROM message_queue
             WHERE recipient_id = ?1
             ORDER BY created_at ASC
             LIMIT ?2",
        )?;
        // usize to i64 for SQLite parameter — safe, max_count is bounded by protocol consts
        #[allow(clippy::cast_possible_wrap)]
        let limit = max_count as i64;
        let rows = stmt
            .query_map((&recipient_id, limit), |row| {
                Ok(QueuedRow {
                    message_id: row.get(0)?,
                    sender_id: row.get(1)?,
                    envelope_json: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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
    pub message_id: String,
    pub sender_id: String,
    pub envelope_json: String,
}

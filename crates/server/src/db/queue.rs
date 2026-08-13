use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

/// Enqueue an encrypted message for delivery.
///
/// Deduplicates on `message_id`. Checks per-user queue depth before inserting.
/// Accepts owned `envelope_json` to avoid cloning ~512KB on the hot path.
pub async fn enqueue(conn: &Connection, request: EnqueueRequest) -> anyhow::Result<EnqueueResult> {
    conn.call(move |conn| {
        // Wrap in transaction to prevent TOCTOU between COUNT and INSERT
        let tx = conn.transaction()?;

        if let Some(result) = classify_existing(&tx, &request)? {
            tx.rollback()?;
            return Ok(result);
        }

        // Check recipient exists (clear result vs FK constraint error)
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = ?1)",
            [&request.recipient_id],
            |row| row.get(0),
        )?;
        if !exists {
            tx.rollback()?;
            return Ok(EnqueueResult::RecipientNotFound);
        }

        // Check per-user queue depth
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM message_queue WHERE recipient_id = ?1",
            [&request.recipient_id],
            |row| row.get(0),
        )?;
        // count is non-negative from COUNT(*); MAX_QUEUE_PER_USER (10,000) fits in i64
        if count >= i64::try_from(request.max_queue_per_user).unwrap_or(i64::MAX) {
            tx.rollback()?;
            return Ok(EnqueueResult::QueueFull);
        }

        tx.execute(
            "DELETE FROM prekey_reservations WHERE expires_at < ?1",
            [request.now],
        )?;
        if let Some(key_id) = request.prekey_id {
            let claimed = tx.execute(
                "UPDATE prekey_reservations SET message_id = ?4
                 WHERE requester_id = ?1 AND target_id = ?2 AND key_id = ?3
                 AND expires_at >= ?5 AND message_id IS NULL",
                (
                    &request.sender_id,
                    &request.recipient_id,
                    key_id,
                    &request.message_id,
                    request.now,
                ),
            )?;
            if claimed == 0 {
                tx.rollback()?;
                return Ok(EnqueueResult::PrekeyReservationInvalid);
            }
        }

        let changed = tx.execute(
            "INSERT OR IGNORE INTO message_queue (message_id, recipient_id, sender_id, envelope)
             VALUES (?1, ?2, ?3, ?4)",
            (
                &request.message_id,
                &request.recipient_id,
                &request.sender_id,
                &request.envelope_json,
            ),
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

pub struct EnqueueRequest {
    pub message_id: String,
    pub recipient_id: String,
    pub sender_id: String,
    pub envelope_json: String,
    pub max_queue_per_user: usize,
    pub prekey_id: Option<u32>,
    pub now: u64,
}

fn classify_existing(
    tx: &rusqlite::Transaction<'_>,
    request: &EnqueueRequest,
) -> rusqlite::Result<Option<EnqueueResult>> {
    let existing = tx
        .query_row(
            "SELECT recipient_id, sender_id, envelope FROM message_queue WHERE message_id = ?1",
            [&request.message_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    Ok(existing.map(|(recipient, sender, envelope)| {
        if recipient == request.recipient_id
            && sender == request.sender_id
            && envelope == request.envelope_json
        {
            EnqueueResult::Duplicate
        } else {
            EnqueueResult::MessageIdConflict
        }
    }))
}

/// Result of attempting to enqueue a message.
#[non_exhaustive]
pub enum EnqueueResult {
    Inserted,
    Duplicate,
    QueueFull,
    RecipientNotFound,
    PrekeyReservationInvalid,
    MessageIdConflict,
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

/// Delete one invalid queued row after it fails durable delivery validation.
pub async fn delete_invalid_row(
    conn: &Connection,
    recipient_id: &str,
    row_id: i64,
) -> anyhow::Result<()> {
    let recipient_id = recipient_id.to_owned();
    conn.call(move |conn| {
        conn.execute(
            "DELETE FROM message_queue WHERE rowid = ?1 AND recipient_id = ?2",
            rusqlite::params![row_id, recipient_id],
        )?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Connection {
        let conn = Connection::open_in_memory().await.unwrap();
        crate::db::schema::initialize(&conn).await.unwrap();
        conn.call(|conn| {
            conn.execute(
                "INSERT INTO users (user_id, identity_key) VALUES ('bob', X'00')",
                [],
            )?;
            conn.execute(
                "INSERT INTO prekey_reservations
                    (requester_id, target_id, key_id, expires_at)
                 VALUES ('alice', 'bob', 7, 200)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        conn
    }

    fn request(
        message_id: &str,
        envelope: &str,
        prekey_id: Option<u32>,
        now: u64,
    ) -> EnqueueRequest {
        EnqueueRequest {
            message_id: message_id.to_owned(),
            recipient_id: "bob".to_owned(),
            sender_id: "alice".to_owned(),
            envelope_json: envelope.to_owned(),
            max_queue_per_user: 10,
            prekey_id,
            now,
        }
    }

    #[tokio::test]
    async fn accepted_message_retry_ignores_expired_reservation() {
        let conn = test_db().await;
        assert!(matches!(
            enqueue(&conn, request("message-1", "ciphertext", Some(7), 100))
                .await
                .unwrap(),
            EnqueueResult::Inserted
        ));
        assert!(matches!(
            enqueue(&conn, request("message-1", "ciphertext", Some(7), 201))
                .await
                .unwrap(),
            EnqueueResult::Duplicate
        ));
        assert!(matches!(
            enqueue(&conn, request("message-2", "ciphertext-2", Some(7), 201))
                .await
                .unwrap(),
            EnqueueResult::PrekeyReservationInvalid
        ));
    }

    #[tokio::test]
    async fn duplicate_id_requires_identical_route_and_payload() {
        let conn = test_db().await;
        enqueue(&conn, request("message-1", "ciphertext", None, 100))
            .await
            .unwrap();
        assert!(matches!(
            enqueue(&conn, request("message-1", "different", None, 100))
                .await
                .unwrap(),
            EnqueueResult::MessageIdConflict
        ));
    }
}

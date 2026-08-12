use tokio_rusqlite::Connection;

pub async fn enqueue(
    connection: &Connection,
    receipt_id: &str,
    recipient_id: &str,
    sender_id: &str,
    envelope: String,
    max_queue_per_user: usize,
) -> anyhow::Result<EnqueueResult> {
    let values = (
        receipt_id.to_owned(),
        recipient_id.to_owned(),
        sender_id.to_owned(),
        envelope,
    );
    connection
        .call(move |connection| {
            let transaction = connection.transaction()?;
            let existing: Option<(String, String, bool)> = transaction
                .query_row(
                    "SELECT recipient_id, sender_id, acknowledged
                     FROM read_receipt_queue WHERE receipt_id = ?1",
                    [&values.0],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if let Some((recipient, sender, acknowledged)) = existing {
                transaction.rollback()?;
                if recipient != values.1 || sender != values.2 {
                    return Ok(EnqueueResult::Collision);
                }
                return Ok(if acknowledged {
                    EnqueueResult::AlreadyAcknowledged
                } else {
                    EnqueueResult::Duplicate
                });
            }
            let count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM read_receipt_queue
                 WHERE recipient_id = ?1 AND acknowledged = 0",
                [&values.1],
                |row| row.get(0),
            )?;
            if count >= i64::try_from(max_queue_per_user).unwrap_or(i64::MAX) {
                transaction.rollback()?;
                return Ok(EnqueueResult::QueueFull);
            }
            let sender_count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM read_receipt_queue WHERE sender_id = ?1",
                [&values.2],
                |row| row.get(0),
            )?;
            if sender_count >= i64::try_from(max_queue_per_user).unwrap_or(i64::MAX) {
                transaction.rollback()?;
                return Ok(EnqueueResult::QueueFull);
            }
            let changed = transaction.execute(
                "INSERT OR IGNORE INTO read_receipt_queue
                    (receipt_id, recipient_id, sender_id, envelope)
                 VALUES (?1, ?2, ?3, ?4)",
                values,
            )?;
            transaction.commit()?;
            Ok(if changed > 0 {
                EnqueueResult::Inserted
            } else {
                EnqueueResult::Duplicate
            })
        })
        .await
        .map_err(Into::into)
}

#[non_exhaustive]
pub enum EnqueueResult {
    Inserted,
    Duplicate,
    AlreadyAcknowledged,
    Collision,
    QueueFull,
}

pub async fn pending(
    connection: &Connection,
    recipient_id: &str,
) -> anyhow::Result<Vec<QueuedReceipt>> {
    let recipient_id = recipient_id.to_owned();
    connection
        .call(move |connection| {
            let mut statement = connection.prepare(
                "SELECT receipt_id, sender_id, envelope
                 FROM read_receipt_queue
                 WHERE recipient_id = ?1 AND acknowledged = 0
                 ORDER BY created_at, rowid LIMIT 1000",
            )?;
            let rows = statement.query_map([recipient_id], |row| {
                Ok(QueuedReceipt {
                    receipt_id: row.get(0)?,
                    sender_id: row.get(1)?,
                    envelope: row.get(2)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
        .map_err(Into::into)
}

pub async fn acknowledge(
    connection: &Connection,
    recipient_id: &str,
    receipt_ids: &[String],
) -> anyhow::Result<Vec<(String, String)>> {
    let recipient_id = recipient_id.to_owned();
    let receipt_ids = receipt_ids.to_vec();
    connection
        .call(move |connection| {
            let transaction = connection.transaction()?;
            let mut acknowledged = Vec::new();
            for receipt_id in receipt_ids {
                let sender: Option<String> = transaction
                    .query_row(
                        "SELECT sender_id FROM read_receipt_queue
                         WHERE receipt_id = ?1 AND recipient_id = ?2",
                        (&receipt_id, &recipient_id),
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(sender) = sender {
                    transaction.execute(
                        "UPDATE read_receipt_queue SET acknowledged = 1
                         WHERE receipt_id = ?1 AND recipient_id = ?2",
                        (&receipt_id, &recipient_id),
                    )?;
                    acknowledged.push((receipt_id, sender));
                }
            }
            transaction.commit()?;
            Ok(acknowledged)
        })
        .await
        .map_err(Into::into)
}

pub async fn confirmed_for_sender(
    connection: &Connection,
    sender_id: &str,
) -> anyhow::Result<Vec<String>> {
    let sender_id = sender_id.to_owned();
    connection
        .call(move |connection| {
            let mut statement = connection.prepare(
                "SELECT receipt_id FROM read_receipt_queue
                 WHERE sender_id = ?1 AND acknowledged = 1
                 ORDER BY created_at, rowid LIMIT 1000",
            )?;
            let rows = statement.query_map([sender_id], |row| row.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
        .map_err(Into::into)
}

pub async fn confirm_sender_received(
    connection: &Connection,
    sender_id: &str,
    receipt_ids: &[String],
) -> anyhow::Result<()> {
    let sender_id = sender_id.to_owned();
    let receipt_ids = receipt_ids.to_vec();
    connection
        .call(move |connection| {
            let transaction = connection.transaction()?;
            for receipt_id in receipt_ids {
                transaction.execute(
                    "DELETE FROM read_receipt_queue
                     WHERE receipt_id = ?1 AND sender_id = ?2 AND acknowledged = 1",
                    (&receipt_id, &sender_id),
                )?;
            }
            transaction.commit()?;
            Ok(())
        })
        .await
        .map_err(Into::into)
}

pub async fn delete_invalid(
    connection: &Connection,
    recipient_id: &str,
    receipt_id: &str,
) -> anyhow::Result<()> {
    let recipient_id = recipient_id.to_owned();
    let receipt_id = receipt_id.to_owned();
    connection
        .call(move |connection| {
            connection.execute(
                "DELETE FROM read_receipt_queue
                 WHERE receipt_id = ?1 AND recipient_id = ?2",
                (&receipt_id, &recipient_id),
            )?;
            Ok(())
        })
        .await
        .map_err(Into::into)
}

use rusqlite::OptionalExtension;

pub struct QueuedReceipt {
    pub receipt_id: String,
    pub sender_id: String,
    pub envelope: String,
}

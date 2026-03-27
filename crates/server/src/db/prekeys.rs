use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

/// Upload a batch of one-time pre-keys for a user.
pub async fn upload_prekeys(
    conn: &Connection,
    user_id: &str,
    prekeys: &[(u32, Vec<u8>)],
) -> anyhow::Result<()> {
    let user_id = user_id.to_owned();
    let prekeys = prekeys.to_vec();

    conn.call(move |conn| {
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO prekeys (user_id, key_id, public_key)
                 VALUES (?1, ?2, ?3)",
            )?;
            for (key_id, public_key) in &prekeys {
                stmt.execute((&user_id, key_id, public_key))?;
            }
        }
        tx.commit()?;
        Ok(())
    })
    .await
    .map_err(Into::into)
}

/// Fetch and atomically delete one one-time pre-key for a user.
/// Returns `(key_id, public_key)` or None if no pre-keys remain.
pub async fn fetch_and_delete_prekey(
    conn: &Connection,
    user_id: &str,
) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
    let user_id = user_id.to_owned();

    conn.call(move |conn| {
        // Atomic fetch+delete using DELETE RETURNING (SQLite 3.35+)
        let result = conn
            .query_row(
                "DELETE FROM prekeys WHERE rowid = (
                    SELECT rowid FROM prekeys WHERE user_id = ?1 LIMIT 1
                 ) RETURNING key_id, public_key",
                (&user_id,),
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        Ok(result)
    })
    .await
    .map_err(Into::into)
}

/// Get the signed pre-key for a user. Returns `(key_id, public_key, signature)`.
pub async fn get_signed_prekey(
    conn: &Connection,
    user_id: &str,
) -> anyhow::Result<Option<(u32, Vec<u8>, Vec<u8>)>> {
    let user_id = user_id.to_owned();

    conn.call(move |conn| {
        let result = conn
            .query_row(
                "SELECT key_id, public_key, signature FROM signed_prekeys
                 WHERE user_id = ?1 ORDER BY key_id DESC LIMIT 1",
                (&user_id,),
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        Ok(result)
    })
    .await
    .map_err(Into::into)
}

/// Count remaining one-time pre-keys for a user.
pub async fn count_prekeys(conn: &Connection, user_id: &str) -> anyhow::Result<u32> {
    let user_id = user_id.to_owned();

    conn.call(move |conn| {
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM prekeys WHERE user_id = ?1",
            (&user_id,),
            |row| row.get(0),
        )?;
        Ok(count)
    })
    .await
    .map_err(Into::into)
}

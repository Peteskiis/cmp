use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

/// Register a new user with their Ed25519 identity public key, signed pre-key,
/// and one-time pre-keys — all in a single transaction.
///
/// Returns `Ok(true)` on success, `Ok(false)` if the user already exists.
pub struct Registration<'a> {
    pub user_id: &'a str,
    pub identity_key: &'a [u8],
    pub signed_prekey_id: u32,
    pub signed_prekey_public: &'a [u8],
    pub signed_prekey_signature: &'a [u8],
    pub one_time_prekeys: &'a [(u32, Vec<u8>)],
}

pub async fn register_atomic(
    conn: &Connection,
    registration: Registration<'_>,
) -> anyhow::Result<bool> {
    let user_id = registration.user_id.to_owned();
    let identity_key = registration.identity_key.to_vec();
    let spk_id = registration.signed_prekey_id;
    let spk_public = registration.signed_prekey_public.to_vec();
    let spk_signature = registration.signed_prekey_signature.to_vec();
    let prekeys = registration.one_time_prekeys.to_vec();

    conn.call(move |conn| {
        let tx = conn.transaction()?;

        // TOFU: first registration wins
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO users (user_id, identity_key) VALUES (?1, ?2)",
            (&user_id, &identity_key),
        )?;
        if inserted == 0 {
            // User already exists — roll back, reject
            tx.rollback()?;
            return Ok(false);
        }

        tx.execute(
            "INSERT OR REPLACE INTO signed_prekeys (user_id, key_id, public_key, signature)
             VALUES (?1, ?2, ?3, ?4)",
            (&user_id, spk_id, &spk_public, &spk_signature),
        )?;

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
        Ok(true)
    })
    .await
    .map_err(Into::into)
}

/// Look up a user's identity key. Returns None if the user doesn't exist.
pub async fn get_identity_key(conn: &Connection, user_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let user_id = user_id.to_owned();

    conn.call(move |conn| {
        let mut stmt = conn.prepare("SELECT identity_key FROM users WHERE user_id = ?1")?;
        let result = stmt
            .query_row((&user_id,), |row| row.get::<_, Vec<u8>>(0))
            .optional()?;
        Ok(result)
    })
    .await
    .map_err(Into::into)
}

/// Check if a user exists.
pub async fn exists(conn: &Connection, user_id: &str) -> anyhow::Result<bool> {
    let user_id = user_id.to_owned();

    conn.call(move |conn| {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = ?1)",
            (&user_id,),
            |row| row.get(0),
        )?;
        Ok(exists)
    })
    .await
    .map_err(Into::into)
}

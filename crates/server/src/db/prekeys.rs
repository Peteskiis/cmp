use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

const PUBLIC_PREKEY_RETENTION_SECS: u64 = protocol::consts::ONE_TIME_PREKEY_PUBLIC_RETENTION_SECS;

/// Upload a batch of one-time pre-keys for a user.
pub async fn upload_prekeys(
    conn: &Connection,
    user_id: &str,
    prekeys: &[(u32, Vec<u8>)],
    max_prekeys_per_user: usize,
) -> anyhow::Result<UploadResult> {
    let user_id = user_id.to_owned();
    let prekeys = prekeys.to_vec();

    conn.call(move |conn| {
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM prekeys WHERE user_id = ?1
             AND created_at < unixepoch() - ?2",
            (&user_id, PUBLIC_PREKEY_RETENTION_SECS),
        )?;
        let high_water: i64 = tx.query_row(
            "SELECT high_water FROM prekey_inventory WHERE user_id = ?1",
            [&user_id],
            |row| row.get(0),
        )?;
        let minimum = prekeys.iter().map(|(key_id, _)| i64::from(*key_id)).min();
        let maximum_id = prekeys.iter().map(|(key_id, _)| i64::from(*key_id)).max();
        let existing: i64 = tx.query_row(
            "SELECT COUNT(*) FROM prekeys WHERE user_id = ?1",
            [&user_id],
            |row| row.get(0),
        )?;
        if maximum_id.is_some_and(|maximum| maximum <= high_water) {
            tx.rollback()?;
            return Ok(UploadResult::Accepted(
                u32::try_from(existing).unwrap_or(u32::MAX),
            ));
        }
        if minimum.is_none_or(|minimum| minimum <= high_water) {
            tx.rollback()?;
            return Ok(UploadResult::InvalidSequence);
        }
        let new_count = i64::try_from(prekeys.len()).unwrap_or(i64::MAX);
        let maximum = i64::try_from(max_prekeys_per_user).unwrap_or(i64::MAX);
        if existing.saturating_add(new_count) > maximum {
            tx.rollback()?;
            return Ok(UploadResult::InventoryFull(
                u32::try_from(existing).unwrap_or(u32::MAX),
            ));
        }
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO prekeys (user_id, key_id, public_key, created_at)
                 VALUES (?1, ?2, ?3, unixepoch())",
            )?;
            for (key_id, public_key) in &prekeys {
                stmt.execute((&user_id, key_id, public_key))?;
            }
        }
        tx.execute(
            "UPDATE prekey_inventory SET high_water = ?2 WHERE user_id = ?1",
            (&user_id, maximum_id.unwrap_or(high_water)),
        )?;
        let remaining: u32 = tx.query_row(
            "SELECT COUNT(*) FROM prekeys WHERE user_id = ?1",
            [&user_id],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(UploadResult::Accepted(remaining))
    })
    .await
    .map_err(Into::into)
}

#[non_exhaustive]
pub enum UploadResult {
    Accepted(u32),
    InventoryFull(u32),
    InvalidSequence,
}

pub async fn fetch_for_requester(
    conn: &Connection,
    requester_id: &str,
    target_id: &str,
    now: u64,
    limits: FetchLimits,
) -> anyhow::Result<FetchResult> {
    let requester_id = requester_id.to_owned();
    let target_id = target_id.to_owned();
    conn.call(move |conn| {
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM prekey_reservations WHERE expires_at < ?1",
            [now],
        )?;
        let cutoff = now.saturating_sub(limits.window_secs);
        let prekey_cutoff = now.saturating_sub(PUBLIC_PREKEY_RETENTION_SECS);
        tx.execute(
            "DELETE FROM prekeys WHERE user_id = ?1 AND created_at < ?2",
            (&target_id, prekey_cutoff),
        )?;
        tx.execute(
            "DELETE FROM prekey_fetch_events WHERE created_at < ?1",
            [cutoff],
        )?;
        let requester_count: u32 = tx.query_row(
            "SELECT COUNT(*) FROM prekey_fetch_events
             WHERE requester_id = ?1 AND created_at >= ?2",
            (&requester_id, cutoff),
            |row| row.get(0),
        )?;
        let target_count: u32 = tx.query_row(
            "SELECT COUNT(*) FROM prekey_fetch_events
             WHERE target_id = ?1 AND created_at >= ?2",
            (&target_id, cutoff),
            |row| row.get(0),
        )?;
        if requester_count >= limits.per_requester {
            tx.rollback()?;
            return Ok(FetchResult::RateLimited);
        }
        if target_count >= limits.per_target {
            tx.rollback()?;
            return Ok(FetchResult::TargetDepleted);
        }
        let prekey = tx
            .query_row(
                "DELETE FROM prekeys WHERE rowid = (
                    SELECT rowid FROM prekeys WHERE user_id = ?1 LIMIT 1
                 ) RETURNING key_id, public_key",
                [&target_id],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        if prekey.is_some() {
            tx.execute(
                "INSERT INTO prekey_fetch_events (requester_id, target_id, created_at)
                 VALUES (?1, ?2, ?3)",
                (&requester_id, &target_id, now),
            )?;
            if let Some((key_id, _)) = &prekey {
                let expires_at =
                    now.saturating_add(protocol::consts::ONE_TIME_PREKEY_RESERVATION_SECS);
                tx.execute(
                    "INSERT INTO prekey_reservations
                        (requester_id, target_id, key_id, expires_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    (&requester_id, &target_id, key_id, expires_at),
                )?;
            }
        }
        tx.commit()?;
        Ok(prekey.map_or(FetchResult::Empty, |(key_id, public_key)| {
            FetchResult::Fetched { key_id, public_key }
        }))
    })
    .await
    .map_err(Into::into)
}

#[derive(Clone, Copy)]
pub struct FetchLimits {
    pub window_secs: u64,
    pub per_requester: u32,
    pub per_target: u32,
}

#[non_exhaustive]
pub enum FetchResult {
    Fetched { key_id: u32, public_key: Vec<u8> },
    Empty,
    TargetDepleted,
    RateLimited,
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
            "SELECT COUNT(*) FROM prekeys WHERE user_id = ?1
             AND created_at >= unixepoch() - ?2",
            (&user_id, PUBLIC_PREKEY_RETENTION_SECS),
            |row| row.get(0),
        )?;
        Ok(count)
    })
    .await
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    async fn test_db() -> Connection {
        let conn = Connection::open_in_memory().await.unwrap();
        crate::db::schema::initialize(&conn).await.unwrap();
        conn
    }

    async fn add_user(conn: &Connection, user_id: &str) {
        let user_id = user_id.to_owned();
        conn.call(move |conn| {
            conn.execute(
                "INSERT INTO users (user_id, identity_key) VALUES (?1, ?2)",
                (&user_id, vec![0_u8; 32]),
            )?;
            conn.execute(
                "INSERT INTO prekey_inventory (user_id, high_water) VALUES (?1, -1)",
                [&user_id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn upload_is_capped_and_duplicate_batches_are_idempotent() {
        let conn = test_db().await;
        add_user(&conn, "alice").await;
        let prekeys: Vec<_> = (0..3).map(|id| (id, vec![0_u8; 32])).collect();

        assert!(matches!(
            upload_prekeys(&conn, "alice", &prekeys, 3).await.unwrap(),
            UploadResult::Accepted(3)
        ));
        let consumed = fetch_for_requester(
            &conn,
            "bob",
            "alice",
            100,
            FetchLimits {
                window_secs: 3_600,
                per_requester: 10,
                per_target: 10,
            },
        )
        .await
        .unwrap();
        assert!(matches!(consumed, FetchResult::Fetched { .. }));
        assert!(matches!(
            upload_prekeys(&conn, "alice", &prekeys, 3).await.unwrap(),
            UploadResult::Accepted(2)
        ));
        assert!(matches!(
            upload_prekeys(&conn, "alice", &[(3, vec![3; 32]), (4, vec![4; 32])], 3,)
                .await
                .unwrap(),
            UploadResult::InventoryFull(2)
        ));
    }

    #[tokio::test]
    async fn expired_public_prekeys_do_not_count_toward_inventory() {
        let conn = test_db().await;
        add_user(&conn, "alice").await;
        upload_prekeys(&conn, "alice", &[(0, vec![0_u8; 32])], 1)
            .await
            .unwrap();
        conn.call(|conn| {
            conn.execute("UPDATE prekeys SET created_at = 0", [])?;
            Ok(())
        })
        .await
        .unwrap();

        assert_eq!(count_prekeys(&conn, "alice").await.unwrap(), 0);
        assert!(matches!(
            upload_prekeys(&conn, "alice", &[(1, vec![1_u8; 32])], 1)
                .await
                .unwrap(),
            UploadResult::Accepted(1)
        ));
    }

    #[tokio::test]
    async fn legacy_upload_below_reserved_floor_is_terminal_without_reinsertion() {
        let conn = test_db().await;
        add_user(&conn, "alice").await;
        conn.call(|conn| {
            conn.execute(
                "UPDATE prekey_inventory SET high_water = ?2 WHERE user_id = ?1",
                ("alice", (1_i64 << 31) - 1),
            )?;
            Ok(())
        })
        .await
        .unwrap();

        assert!(matches!(
            upload_prekeys(&conn, "alice", &[(100, vec![0_u8; 32])], 10)
                .await
                .unwrap(),
            UploadResult::Accepted(0)
        ));
        assert_eq!(count_prekeys(&conn, "alice").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn fetch_limits_apply_per_requester_and_target() {
        let conn = test_db().await;
        add_user(&conn, "target").await;
        let prekeys: Vec<_> = (0..6).map(|id| (id, vec![0_u8; 32])).collect();
        upload_prekeys(&conn, "target", &prekeys, 10).await.unwrap();
        let limits = FetchLimits {
            window_secs: 3_600,
            per_requester: 2,
            per_target: 3,
        };

        for _ in 0..2 {
            assert!(matches!(
                fetch_for_requester(&conn, "alice", "target", 100, limits)
                    .await
                    .unwrap(),
                FetchResult::Fetched { .. }
            ));
        }
        assert!(matches!(
            fetch_for_requester(&conn, "alice", "target", 100, limits)
                .await
                .unwrap(),
            FetchResult::RateLimited
        ));
        assert!(matches!(
            fetch_for_requester(&conn, "bob", "target", 100, limits)
                .await
                .unwrap(),
            FetchResult::Fetched { .. }
        ));
        assert!(matches!(
            fetch_for_requester(&conn, "carol", "target", 100, limits)
                .await
                .unwrap(),
            FetchResult::TargetDepleted
        ));
    }

    #[tokio::test]
    async fn concurrent_fetches_consume_each_prekey_once() {
        let conn = test_db().await;
        add_user(&conn, "target").await;
        let prekeys: Vec<_> = (0..10).map(|id| (id, vec![0_u8; 32])).collect();
        upload_prekeys(&conn, "target", &prekeys, 10).await.unwrap();
        let limits = FetchLimits {
            window_secs: 3_600,
            per_requester: 100,
            per_target: 100,
        };
        let mut tasks = Vec::new();
        for requester in 0..10 {
            let conn = conn.clone();
            tasks.push(tokio::spawn(async move {
                fetch_for_requester(
                    &conn,
                    &format!("requester-{requester}"),
                    "target",
                    100,
                    limits,
                )
                .await
                .unwrap()
            }));
        }

        let mut key_ids = HashSet::new();
        for task in tasks {
            let result = task.await.unwrap();
            assert!(matches!(result, FetchResult::Fetched { .. }));
            if let FetchResult::Fetched { key_id, .. } = result {
                assert!(key_ids.insert(key_id));
            }
        }
        assert_eq!(key_ids.len(), 10);
        assert_eq!(count_prekeys(&conn, "target").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn fetch_creates_bound_reservation() {
        let conn = test_db().await;
        add_user(&conn, "target").await;
        upload_prekeys(&conn, "target", &[(0, vec![0_u8; 32])], 10)
            .await
            .unwrap();
        let limits = FetchLimits {
            window_secs: 3_600,
            per_requester: 10,
            per_target: 10,
        };
        let fetched = fetch_for_requester(&conn, "alice", "target", 100, limits)
            .await
            .unwrap();
        assert!(matches!(fetched, FetchResult::Fetched { key_id: 0, .. }));
        conn.call(|conn| {
            let reservation: (String, String, u32, u64) = conn.query_row(
                "SELECT requester_id, target_id, key_id, expires_at
                 FROM prekey_reservations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
            assert_eq!(reservation.0, "alice");
            assert_eq!(reservation.1, "target");
            assert_eq!(reservation.2, 0);
            assert_eq!(
                reservation.3,
                100 + protocol::consts::ONE_TIME_PREKEY_RESERVATION_SECS
            );
            Ok(())
        })
        .await
        .unwrap();
    }
}

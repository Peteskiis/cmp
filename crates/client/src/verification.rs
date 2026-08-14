//! Safety number verification: compute fingerprints, track peer identity keys,
//! detect identity key changes.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crypto::fingerprint::Fingerprint;
use rusqlite::Connection;

use crate::app::ChatEntry;
use crate::db;

/// Check and store a peer's identity key.
/// Returns a warning string if the key changed, `None` otherwise.
#[allow(clippy::cognitive_complexity)] // tracing macros inflate the metric
pub(crate) fn check_peer_identity(
    conn: &Connection,
    peer_id: &str,
    identity_key_b64: &str,
) -> Option<String> {
    // Reject malformed keys before touching the DB.
    if decode_identity_key(identity_key_b64).is_err() {
        tracing::warn!("ignoring malformed identity key from {peer_id}");
        return None;
    }
    match db::store_peer_identity_key(conn, peer_id, identity_key_b64) {
        Ok(db::IdentityKeyStatus::Changed { .. }) => Some(format!(
            "security alert: {peer_id}'s identity key has changed! \
             Previous verification is no longer valid. \
             Open verification to see the new safety number."
        )),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!("failed to store peer identity key: {e}");
            None
        }
    }
}

/// Route verification view, confirm, and clear actions to the appropriate handler.
pub(crate) fn handle_action(
    local_user_id: &str,
    local_key_b64: &str,
    peer_id: &str,
    text: &str,
    conn: Option<&Connection>,
) -> Vec<ChatEntry> {
    if text == "clear" {
        return clear_verification(peer_id, conn);
    }
    if text == "confirm" {
        let Some(conn) = conn else {
            return vec![ChatEntry::Status("database unavailable".to_owned())];
        };
        return confirm_verification(local_user_id, local_key_b64, peer_id, conn);
    }
    format_verify_output(local_user_id, local_key_b64, peer_id, conn)
}

fn clear_verification(peer_id: &str, conn: Option<&Connection>) -> Vec<ChatEntry> {
    let Some(conn) = conn else {
        return vec![ChatEntry::Status("database unavailable".to_owned())];
    };
    match db::remove_verification(conn, peer_id) {
        Ok(()) => vec![ChatEntry::Status(format!(
            "verification cleared for {peer_id}"
        ))],
        Err(e) => {
            tracing::warn!("failed to clear verification: {e}");
            vec![ChatEntry::Status("failed to clear verification".to_owned())]
        }
    }
}

/// Resolve peer key from DB and compute the safety number.
fn resolve_safety_number(
    local_user_id: &str,
    local_key_b64: &str,
    peer_id: &str,
    conn: &Connection,
) -> Result<String, ChatEntry> {
    let Some(peer_key_b64) = db::get_peer_identity_key(conn, peer_id) else {
        return Err(ChatEntry::Status(format!(
            "no identity key stored for {peer_id} — send or receive a message first"
        )));
    };
    let local_key = decode_identity_key(local_key_b64)
        .map_err(|e| ChatEntry::Status(format!("failed to compute safety number: {e}")))?;
    let peer_key = decode_identity_key(&peer_key_b64)
        .map_err(|e| ChatEntry::Status(format!("failed to compute safety number: {e}")))?;
    let fp = Fingerprint::compute(local_user_id, &local_key, peer_id, &peer_key);
    Ok(fp.display_grouped())
}

fn format_verify_output(
    local_user_id: &str,
    local_key_b64: &str,
    peer_id: &str,
    conn: Option<&Connection>,
) -> Vec<ChatEntry> {
    let Some(conn) = conn else {
        return vec![ChatEntry::Status("database unavailable".to_owned())];
    };
    let safety_number = match resolve_safety_number(local_user_id, local_key_b64, peer_id, conn) {
        Ok(sn) => sn,
        Err(entry) => return vec![entry],
    };

    let mut lines = vec![ChatEntry::Status(format!("safety number with {peer_id}:"))];

    // 3 rows x 4 groups
    let groups: Vec<&str> = safety_number.split(' ').collect();
    for row in groups.chunks(4) {
        lines.push(ChatEntry::Status(format!("  {}", row.join(" "))));
    }

    lines.push(ChatEntry::Status(
        "compare this number with your contact out-of-band to verify E2EE".to_owned(),
    ));

    match db::get_verification(conn, peer_id) {
        Some(stored_fp) if stored_fp == safety_number => {
            lines.push(ChatEntry::Status(
                "\u{2705} this contact is verified".to_owned(),
            ));
        }
        Some(_) => {
            lines.push(ChatEntry::Warning(
                "stored verification is outdated — key has changed since verification".to_owned(),
            ));
        }
        None => {
            lines.push(ChatEntry::Status(
                "not yet verified — press y after comparing numbers".to_owned(),
            ));
        }
    }

    lines
}

fn confirm_verification(
    local_user_id: &str,
    local_key_b64: &str,
    peer_id: &str,
    conn: &Connection,
) -> Vec<ChatEntry> {
    let safety_number = match resolve_safety_number(local_user_id, local_key_b64, peer_id, conn) {
        Ok(sn) => sn,
        Err(entry) => return vec![entry],
    };

    match db::store_verification(conn, peer_id, &safety_number) {
        Ok(()) => vec![ChatEntry::Status(format!(
            "\u{2705} {peer_id} marked as verified"
        ))],
        Err(e) => {
            tracing::warn!("failed to store verification: {e}");
            vec![ChatEntry::Status("failed to store verification".to_owned())]
        }
    }
}

fn decode_identity_key(b64: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = B64.decode(b64)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("identity key must be 32 bytes"))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp_db() -> (Connection, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let conn = crate::db::open(&path).unwrap();
        (conn, dir)
    }

    #[test]
    fn safety_number_is_symmetric() {
        let key_a = B64.encode([0xAAu8; 32]);
        let key_b = B64.encode([0xBBu8; 32]);
        let local_key = decode_identity_key(&key_a).unwrap();
        let peer_key = decode_identity_key(&key_b).unwrap();
        let sn1 = Fingerprint::compute("alice", &local_key, "bob", &peer_key).display_grouped();
        let sn2 = Fingerprint::compute("bob", &peer_key, "alice", &local_key).display_grouped();
        assert_eq!(sn1, sn2);
    }

    #[test]
    fn identity_key_change_detected() {
        let (conn, _dir) = open_temp_db();
        let key1 = B64.encode([1u8; 32]);
        let key2 = B64.encode([2u8; 32]);

        assert!(matches!(
            db::store_peer_identity_key(&conn, "bob", &key1).unwrap(),
            db::IdentityKeyStatus::New
        ));

        assert!(matches!(
            db::store_peer_identity_key(&conn, "bob", &key1).unwrap(),
            db::IdentityKeyStatus::Unchanged
        ));

        assert!(matches!(
            db::store_peer_identity_key(&conn, "bob", &key2).unwrap(),
            db::IdentityKeyStatus::Changed { .. }
        ));
    }

    #[test]
    fn verification_invalidated_on_key_change() {
        let (conn, _dir) = open_temp_db();
        let key1 = B64.encode([1u8; 32]);
        let key2 = B64.encode([2u8; 32]);

        db::store_peer_identity_key(&conn, "bob", &key1).unwrap();
        db::store_verification(&conn, "bob", "12345 67890").unwrap();
        assert!(db::get_verification(&conn, "bob").is_some());

        db::store_peer_identity_key(&conn, "bob", &key2).unwrap();
        assert!(db::get_verification(&conn, "bob").is_none());
    }

    #[test]
    fn verify_output_without_stored_key() {
        let key = B64.encode([1u8; 32]);
        let (conn, _dir) = open_temp_db();
        let lines = format_verify_output("alice", &key, "bob", Some(&conn));
        assert_eq!(lines.len(), 1);
        assert!(matches!(&lines[0], ChatEntry::Status(s) if s.contains("no identity key")));
    }

    #[test]
    fn verify_output_with_stored_key() {
        let key_a = B64.encode([1u8; 32]);
        let key_b = B64.encode([2u8; 32]);
        let (conn, _dir) = open_temp_db();

        db::store_peer_identity_key(&conn, "bob", &key_b).unwrap();
        let lines = format_verify_output("alice", &key_a, "bob", Some(&conn));

        // header + 3 rows of digits + explanation + verification status
        assert!(lines.len() >= 5);
        assert!(matches!(&lines[1], ChatEntry::Status(s) if s.chars().any(|c| c.is_ascii_digit())));
    }

    #[test]
    fn confirm_stores_verification() {
        let key_a = B64.encode([1u8; 32]);
        let key_b = B64.encode([2u8; 32]);
        let (conn, _dir) = open_temp_db();

        db::store_peer_identity_key(&conn, "bob", &key_b).unwrap();
        let lines = confirm_verification("alice", &key_a, "bob", &conn);
        assert!(matches!(&lines[0], ChatEntry::Status(s) if s.contains("verified")));

        let lines = format_verify_output("alice", &key_a, "bob", Some(&conn));
        let has_verified = lines
            .iter()
            .any(|l| matches!(l, ChatEntry::Status(s) if s.contains("verified")));
        assert!(has_verified);
    }

    #[test]
    fn malformed_key_rejected_without_db_mutation() {
        let (conn, _dir) = open_temp_db();
        let good_key = B64.encode([1u8; 32]);

        // Store a valid key first
        db::store_peer_identity_key(&conn, "bob", &good_key).unwrap();

        // Non-base64 string — rejected, DB unchanged
        assert!(check_peer_identity(&conn, "bob", "not-valid-base64!!!").is_none());
        assert_eq!(
            db::get_peer_identity_key(&conn, "bob").as_deref(),
            Some(good_key.as_str())
        );

        // Base64 but wrong length (16 bytes instead of 32)
        let short_key = B64.encode([2u8; 16]);
        assert!(check_peer_identity(&conn, "bob", &short_key).is_none());
        assert_eq!(
            db::get_peer_identity_key(&conn, "bob").as_deref(),
            Some(good_key.as_str())
        );
    }

    #[test]
    fn clear_verification_removes_record() {
        let key_a = B64.encode([1u8; 32]);
        let key_b = B64.encode([2u8; 32]);
        let (conn, _dir) = open_temp_db();

        db::store_peer_identity_key(&conn, "bob", &key_b).unwrap();
        confirm_verification("alice", &key_a, "bob", &conn);
        assert!(db::get_verification(&conn, "bob").is_some());

        let lines = clear_verification("bob", Some(&conn));
        assert!(matches!(&lines[0], ChatEntry::Status(s) if s.contains("cleared")));
        assert!(db::get_verification(&conn, "bob").is_none());
    }
}

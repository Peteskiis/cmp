use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use protocol::{OneTimePreKey, PreKeyBundle, ServerMessage, UserId, consts};
use rand::RngCore;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{Session, auth_failure, decode_prekeys, error_400, error_500_generic, now_secs};
use crate::db;
use crate::state::AppState;

pub(crate) struct PendingChallenge {
    pub user_id: String,
    pub nonce: [u8; 32],
    pub timestamp: u64,
}

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn handle_register(
    state: &AppState,
    tx: &mpsc::Sender<ServerMessage>,
    session: &mut Session,
    user_id: UserId,
    bundle: PreKeyBundle,
    one_time_prekeys: Vec<OneTimePreKey>,
) -> ServerMessage {
    if session.authed_user.is_some() {
        return auth_failure("already authenticated");
    }

    let uid = user_id.as_str();

    if one_time_prekeys.len() > consts::MAX_PREKEYS_PER_UPLOAD {
        return error_400("too many prekeys");
    }

    // Validate identity key as real Ed25519
    let Ok(identity_bytes) = B64.decode(&bundle.identity_key) else {
        return auth_failure("invalid base64 in identity_key");
    };
    let Ok(ik_arr): Result<[u8; 32], _> = identity_bytes.as_slice().try_into() else {
        return auth_failure("identity key must be 32 bytes");
    };
    let Ok(identity_vk) = VerifyingKey::from_bytes(&ik_arr) else {
        return auth_failure("identity key is not a valid Ed25519 public key");
    };

    let Ok(spk_bytes) = B64.decode(&bundle.signed_prekey) else {
        return auth_failure("invalid base64 in signed_prekey");
    };
    if spk_bytes.len() != 32 {
        return auth_failure("signed prekey must be 32 bytes");
    }
    let Ok(sig_bytes) = B64.decode(&bundle.signed_prekey_signature) else {
        return auth_failure("invalid base64 in signature");
    };

    // Verify SPK signature — defense-in-depth
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return auth_failure("signature must be 64 bytes");
    };
    let spk_sig = Signature::from_bytes(&sig_arr);
    if identity_vk.verify(&spk_bytes, &spk_sig).is_err() {
        return auth_failure("signed prekey signature is invalid");
    }

    let prekey_pairs = match decode_prekeys(&one_time_prekeys) {
        Ok(p) => p,
        Err(msg) => return msg,
    };

    match db::users::register_atomic(
        &state.db,
        db::users::Registration {
            user_id: uid,
            identity_key: &identity_bytes,
            signed_prekey_id: bundle.signed_prekey_id,
            signed_prekey_public: &spk_bytes,
            signed_prekey_signature: &sig_bytes,
            one_time_prekeys: &prekey_pairs,
        },
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return auth_failure("user already exists — use AuthChallenge to login"),
        Err(e) => {
            return {
                tracing::error!("registration failed: {e}");
                error_500_generic()
            };
        }
    }

    session.authed_user = Some(uid.to_owned());
    session.conn_id = Some(state.connections.insert(uid.to_owned(), tx.clone()));
    info!(user_id = uid, "registered and authenticated");

    ServerMessage::AuthSuccess
}

pub(crate) async fn handle_auth_challenge(
    state: &AppState,
    session: &mut Session,
    user_id: UserId,
) -> ServerMessage {
    if session.authed_user.is_some() {
        return auth_failure("already authenticated");
    }

    let uid = user_id.as_str();

    match db::users::exists(&state.db, uid).await {
        Ok(true) => {}
        Ok(false) => return auth_failure("authentication failed"),
        Err(e) => {
            return {
                tracing::error!("db error: {e}");
                error_500_generic()
            };
        }
    }

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let timestamp = now_secs();

    session.pending_challenge = Some(PendingChallenge {
        user_id: uid.to_owned(),
        nonce,
        timestamp,
    });

    ServerMessage::Challenge {
        nonce: B64.encode(nonce),
        timestamp,
        server_id: state.server_id.clone(),
    }
}

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn handle_auth_response(
    state: &AppState,
    tx: &mpsc::Sender<ServerMessage>,
    session: &mut Session,
    signature_b64: String,
) -> ServerMessage {
    if session.authed_user.is_some() {
        return auth_failure("already authenticated");
    }

    let Some(challenge) = session.pending_challenge.take() else {
        return auth_failure("no pending challenge");
    };

    if now_secs().saturating_sub(challenge.timestamp) > 60 {
        return auth_failure("challenge expired");
    }

    let identity_bytes = match db::users::get_identity_key(&state.db, &challenge.user_id).await {
        Ok(Some(k)) => k,
        Ok(None) => return auth_failure("authentication failed"),
        Err(e) => {
            return {
                tracing::error!("db error: {e}");
                error_500_generic()
            };
        }
    };

    let Ok(vk_bytes): Result<[u8; 32], _> = identity_bytes.try_into() else {
        return auth_failure("invalid stored identity key");
    };
    let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) else {
        return auth_failure("invalid stored identity key");
    };

    let Ok(sig_bytes) = B64.decode(&signature_b64) else {
        return auth_failure("invalid base64 signature");
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return auth_failure("signature must be 64 bytes");
    };
    let signature = Signature::from_bytes(&sig_arr);

    let mut signed_data = Vec::with_capacity(32 + 8 + state.server_id.len());
    signed_data.extend_from_slice(&challenge.nonce);
    signed_data.extend_from_slice(&challenge.timestamp.to_be_bytes());
    signed_data.extend_from_slice(state.server_id.as_bytes());

    if vk.verify(&signed_data, &signature).is_err() {
        return auth_failure("signature verification failed");
    }

    // Move user_id out of challenge to avoid double-clone
    let user_id = challenge.user_id;
    session.conn_id = Some(state.connections.insert(user_id.clone(), tx.clone()));
    session.authed_user = Some(user_id.clone());
    info!(user_id, "authenticated");

    ServerMessage::AuthSuccess
}

/// Deliver queued messages to a freshly authenticated user.
/// Called by `ws.rs` after `AuthSuccess` is on the wire.
#[allow(clippy::cognitive_complexity)]
pub(crate) async fn deliver_queued_messages(
    state: &AppState,
    tx: &mpsc::Sender<ServerMessage>,
    user_id: &str,
) {
    let empty_page_bytes = match serde_json::to_vec(&ServerMessage::QueuedMessages {
        messages: Vec::new(),
    }) {
        Ok(encoded) => encoded.len(),
        Err(error) => {
            warn!(user_id, "failed to size queued page: {error}");
            return;
        }
    };
    let mut cursor = 0;
    let mut visited = 0;
    let mut page = Vec::new();
    let mut page_bytes = empty_page_bytes;

    while visited < consts::MAX_QUEUED_MESSAGES {
        let row = match db::queue::get_next_pending(&state.db, user_id, cursor).await {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(error) => {
                warn!(user_id, "failed to fetch queued message: {error}");
                return;
            }
        };
        cursor = row.row_id;
        visited += 1;

        let message = match queued_row_to_inbound(&row) {
            Ok(message) => message,
            Err(error) => {
                warn!(
                    message_id = row.message_id,
                    "invalid queued message: {error}"
                );
                remove_invalid_queued_row(state, user_id, row.row_id).await;
                continue;
            }
        };
        let item_bytes = match serde_json::to_vec(&message) {
            Ok(encoded) => encoded.len(),
            Err(error) => {
                warn!(user_id, "failed to size queued message: {error}");
                remove_invalid_queued_row(state, user_id, row.row_id).await;
                continue;
            }
        };
        let separator_bytes = usize::from(!page.is_empty());
        if empty_page_bytes + item_bytes > consts::MAX_QUEUED_PAGE_BYTES {
            warn!(
                message_id = row.message_id,
                "queued message exceeds WebSocket page limit"
            );
            remove_invalid_queued_row(state, user_id, row.row_id).await;
            continue;
        }
        let page_full = page.len() >= consts::MAX_QUEUED_MESSAGES_PER_PAGE
            || page_bytes + separator_bytes + item_bytes > consts::MAX_QUEUED_PAGE_BYTES;

        if page_full {
            if !send_queued_page(state, tx, std::mem::take(&mut page)).await {
                return;
            }
            page_bytes = empty_page_bytes;
        }

        page_bytes += usize::from(!page.is_empty()) + item_bytes;
        page.push(message);
    }

    if !page.is_empty() {
        let _ = send_queued_page(state, tx, page).await;
    }
}

pub(crate) async fn deliver_queued_receipts(
    state: &AppState,
    tx: &mpsc::Sender<ServerMessage>,
    user_id: &str,
) {
    let receipts = load_queued_receipts(state, user_id)
        .await
        .unwrap_or_default();
    for receipt in receipts {
        let Some(message) = queued_receipt_to_message(&receipt) else {
            remove_invalid_receipt(state, user_id, &receipt.receipt_id).await;
            continue;
        };
        if tx.send(message).await.is_err() {
            return;
        }
    }
    deliver_receipt_confirmations(state, tx, user_id).await;
}

async fn deliver_receipt_confirmations(
    state: &AppState,
    tx: &mpsc::Sender<ServerMessage>,
    user_id: &str,
) {
    let receipt_ids = load_receipt_confirmations(state, user_id)
        .await
        .unwrap_or_default();
    for receipt_id in receipt_ids {
        let Ok(receipt_id) = uuid::Uuid::parse_str(&receipt_id) else {
            continue;
        };
        if tx
            .send(ServerMessage::ReadReceiptSent {
                receipt_id: receipt_id.into(),
            })
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn load_receipt_confirmations(state: &AppState, user_id: &str) -> Option<Vec<String>> {
    match db::receipts::confirmed_for_sender(&state.db, user_id).await {
        Ok(receipt_ids) => Some(receipt_ids),
        Err(error) => {
            warn!(
                user_id,
                "failed to fetch read receipt confirmations: {error}"
            );
            None
        }
    }
}

async fn load_queued_receipts(
    state: &AppState,
    user_id: &str,
) -> Option<Vec<db::receipts::QueuedReceipt>> {
    match db::receipts::pending(&state.db, user_id).await {
        Ok(receipts) => Some(receipts),
        Err(error) => {
            warn!(user_id, "failed to fetch queued read receipts: {error}");
            None
        }
    }
}

fn queued_receipt_to_message(receipt: &db::receipts::QueuedReceipt) -> Option<ServerMessage> {
    let receipt_id = uuid::Uuid::parse_str(&receipt.receipt_id).ok()?;
    let sender_id = protocol::UserId::new(&receipt.sender_id).ok()?;
    let envelope = serde_json::from_str(&receipt.envelope).ok()?;
    super::message::validate_envelope(&envelope).ok()?;
    Some(ServerMessage::IncomingReadReceipt {
        sender_id,
        receipt_id: receipt_id.into(),
        envelope,
    })
}

async fn remove_invalid_receipt(state: &AppState, user_id: &str, receipt_id: &str) {
    if let Err(error) = db::receipts::delete_invalid(&state.db, user_id, receipt_id).await {
        warn!(
            user_id,
            receipt_id, "failed to remove invalid queued read receipt: {error}"
        );
    }
}

async fn remove_invalid_queued_row(state: &AppState, user_id: &str, row_id: i64) {
    if let Err(error) = db::queue::delete_invalid_row(&state.db, user_id, row_id).await {
        warn!(
            user_id,
            row_id, "failed to remove invalid queued message: {error}"
        );
    }
}

async fn send_queued_page(
    state: &AppState,
    tx: &mpsc::Sender<ServerMessage>,
    messages: Vec<protocol::InboundMessage>,
) -> bool {
    let mut delivery_by_sender: std::collections::HashMap<String, Vec<protocol::MessageId>> =
        std::collections::HashMap::new();
    for message in &messages {
        delivery_by_sender
            .entry(message.sender_id.as_str().to_owned())
            .or_default()
            .push(message.message_id.clone());
    }

    if tx
        .send(ServerMessage::QueuedMessages { messages })
        .await
        .is_err()
    {
        return false;
    }

    for (sender, ids) in delivery_by_sender {
        state.connections.send_to(
            &sender,
            ServerMessage::MessageDelivered { message_ids: ids },
        );
    }
    true
}

fn queued_row_to_inbound(row: &db::queue::QueuedRow) -> anyhow::Result<protocol::InboundMessage> {
    let envelope = serde_json::from_str(&row.envelope_json)?;
    super::message::validate_envelope(&envelope).map_err(anyhow::Error::msg)?;
    let sender_id = protocol::UserId::new(&row.sender_id)?;
    let message_id = protocol::MessageId::from(uuid::Uuid::parse_str(&row.message_id)?);
    Ok(protocol::InboundMessage {
        message_id,
        sender_id,
        envelope,
        timestamp: parse_sqlite_datetime(&row.created_at),
    })
}

/// Parse `SQLite` `datetime('now')` format (`YYYY-MM-DD HH:MM:SS`) to unix timestamp.
/// Returns 0 on parse failure — best effort.
fn parse_sqlite_datetime(s: &str) -> u64 {
    // SQLite datetime format: "2024-01-15 10:30:45"
    // Parse manually to avoid adding a datetime dependency
    let parts: Vec<&str> = s.split(['-', ' ', ':']).collect();
    if parts.len() != 6 {
        return 0;
    }
    let Ok(year): Result<i64, _> = parts[0].parse() else {
        return 0;
    };
    let Ok(month): Result<i64, _> = parts[1].parse() else {
        return 0;
    };
    let Ok(day): Result<i64, _> = parts[2].parse() else {
        return 0;
    };
    let Ok(hour): Result<i64, _> = parts[3].parse() else {
        return 0;
    };
    let Ok(min): Result<i64, _> = parts[4].parse() else {
        return 0;
    };
    let Ok(sec): Result<i64, _> = parts[5].parse() else {
        return 0;
    };

    // Simplified days-since-epoch (no leap second precision needed for message ordering)
    let days = (year - 1970) * 365 + (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;
    let month_days: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let leap_adj = i64::from(is_leap && month > 2);
    let m_idx = (month - 1).clamp(0, 11);
    // All components derive from datetime('now') which is always >= 1970,
    // so the sum is non-negative. cast_sign_loss is safe.
    #[allow(clippy::cast_sign_loss)]
    let total = ((days + month_days[m_idx as usize] + day - 1 + leap_adj) * 86400
        + hour * 3600
        + min * 60
        + sec) as u64;
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_invalid_envelope_is_rejected_before_delivery() {
        let envelope = protocol::EncryptedEnvelope {
            version: 1,
            header: protocol::types::MessageHeader::Ratchet(protocol::types::RatchetHeader {
                ratchet_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    [0_u8; 31],
                ),
                previous_chain_length: 0,
                message_number: 0,
            }),
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"opaque",
            ),
        };
        let row = db::queue::QueuedRow {
            row_id: 1,
            message_id: uuid::Uuid::new_v4().to_string(),
            sender_id: "alice".to_owned(),
            envelope_json: serde_json::to_string(&envelope).unwrap(),
            created_at: "2026-08-12 00:00:00".to_owned(),
        };

        assert!(queued_row_to_inbound(&row).is_err());
    }
}

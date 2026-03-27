use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use protocol::{OneTimePreKey, PreKeyBundle, ServerMessage, UserId, consts};
use rand::RngCore;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{Session, auth_failure, decode_prekeys, error_400, error_500_generic};
use crate::db;
use crate::state::AppState;

pub struct PendingChallenge {
    pub user_id: String,
    pub nonce: [u8; 32],
    pub timestamp: u64,
}

#[allow(clippy::cognitive_complexity)]
pub async fn handle_register(
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
        uid,
        &identity_bytes,
        bundle.signed_prekey_id,
        &spk_bytes,
        &sig_bytes,
        &prekey_pairs,
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

pub async fn handle_auth_challenge(
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
        Ok(false) => return auth_failure("user not found"),
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
pub async fn handle_auth_response(
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
        Ok(None) => return auth_failure("user not found"),
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
pub async fn deliver_queued_messages(
    state: &AppState,
    tx: &mpsc::Sender<ServerMessage>,
    user_id: &str,
) {
    let queued = match db::queue::get_pending(&state.db, user_id, consts::MAX_QUEUED_MESSAGES).await
    {
        Ok(q) if !q.is_empty() => q,
        Ok(_) => return,
        Err(e) => {
            warn!(user_id, "failed to fetch queued messages: {e}");
            return;
        }
    };

    let messages: Vec<protocol::InboundMessage> = queued
        .into_iter()
        .filter_map(|row| {
            let envelope = match serde_json::from_str(&row.envelope_json) {
                Ok(e) => e,
                Err(e) => {
                    warn!(
                        message_id = row.message_id,
                        "malformed queued envelope: {e}"
                    );
                    return None;
                }
            };
            let sender_id = match protocol::UserId::new(&row.sender_id) {
                Ok(id) => id,
                Err(e) => {
                    warn!(message_id = row.message_id, "invalid sender_id: {e}");
                    return None;
                }
            };
            let message_id = match uuid::Uuid::parse_str(&row.message_id) {
                Ok(uuid) => protocol::MessageId::from(uuid),
                Err(e) => {
                    warn!(message_id = row.message_id, "invalid message_id: {e}");
                    return None;
                }
            };
            // Parse SQLite datetime string to unix timestamp
            let timestamp = parse_sqlite_datetime(&row.created_at);
            Some(protocol::InboundMessage {
                message_id,
                sender_id,
                envelope,
                timestamp,
            })
        })
        .collect();

    if !messages.is_empty() {
        let _ = tx.try_send(ServerMessage::QueuedMessages { messages });
    }
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
    #[allow(clippy::cast_sign_loss)]
    let total = ((days + month_days[m_idx as usize] + day - 1 + leap_adj) * 86400
        + hour * 3600
        + min * 60
        + sec) as u64;
    total
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

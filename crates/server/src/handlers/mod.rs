pub(crate) mod auth;
pub(crate) mod message;
pub(crate) mod prekey;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use protocol::{ClientMessage, OneTimePreKey, ServerMessage};
use tokio::sync::mpsc;
use tracing::warn;

use crate::state::AppState;

type DecodedPreKey = (u32, Vec<u8>);

/// Per-connection session state — travels together through handlers.
pub(crate) struct Session {
    pub authed_user: Option<String>,
    pub conn_id: Option<u64>,
    pub pending_challenge: Option<auth::PendingChallenge>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub(crate) const fn new() -> Self {
        Self {
            authed_user: None,
            conn_id: None,
            pending_challenge: None,
        }
    }
}

// ── Shared helpers ──

pub(crate) fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

// ── Shared error helpers ──

pub(crate) fn auth_failure(reason: &str) -> ServerMessage {
    ServerMessage::AuthFailure {
        reason: reason.to_owned(),
    }
}

pub(crate) fn error_400(message: &str) -> ServerMessage {
    ServerMessage::Error {
        code: 400,
        message: message.to_owned(),
    }
}

pub(crate) fn error_404(message: &str) -> ServerMessage {
    ServerMessage::Error {
        code: 404,
        message: message.to_owned(),
    }
}

/// Returns a generic 500 error to the client. Callers must log the real error
/// separately with `tracing` — never send internal details over the wire.
pub(crate) fn error_500_generic() -> ServerMessage {
    ServerMessage::Error {
        code: 500,
        message: "internal server error".to_owned(),
    }
}

/// Decode a batch of base64-encoded one-time prekeys.
/// Rejects the entire batch if any key has invalid base64.
#[allow(clippy::result_large_err)] // ServerMessage is the wire type; boxing adds no value here.
pub(crate) fn decode_prekeys(
    prekeys: &[OneTimePreKey],
) -> Result<Vec<DecodedPreKey>, ServerMessage> {
    let pairs: Vec<DecodedPreKey> = prekeys
        .iter()
        .filter_map(|pk| {
            let bytes = B64.decode(&pk.public_key).ok()?;
            // X25519 public keys must be exactly 32 bytes
            if bytes.len() != 32 {
                return None;
            }
            Some((pk.key_id, bytes))
        })
        .collect();
    if pairs.len() != prekeys.len() {
        return Err(error_400(
            "one or more prekeys have invalid base64 or wrong length (must be 32 bytes)",
        ));
    }
    Ok(pairs)
}

/// Route a client message to the appropriate handler.
#[allow(clippy::cognitive_complexity)] // Inherent in a message router.
pub(crate) async fn handle_message(
    state: &AppState,
    tx: &mpsc::Sender<ServerMessage>,
    session: &mut Session,
    msg: ClientMessage,
) -> Option<ServerMessage> {
    // Auth messages are always allowed
    match msg {
        ClientMessage::Register { .. }
        | ClientMessage::AuthChallenge { .. }
        | ClientMessage::AuthResponse { .. } => {}
        _ => {
            if session.authed_user.is_none() {
                return Some(auth_failure("not authenticated"));
            }
        }
    }

    match msg {
        ClientMessage::Register {
            user_id,
            bundle,
            one_time_prekeys,
        } => {
            Some(auth::handle_register(state, tx, session, user_id, bundle, one_time_prekeys).await)
        }
        ClientMessage::AuthChallenge { user_id } => {
            Some(auth::handle_auth_challenge(state, session, user_id).await)
        }
        ClientMessage::AuthResponse { signature } => {
            Some(auth::handle_auth_response(state, tx, session, signature).await)
        }
        ClientMessage::UploadPreKeys { prekeys } => {
            let user_id = session.authed_user.as_ref()?;
            Some(prekey::handle_upload(state, user_id, prekeys).await)
        }
        ClientMessage::FetchPreKeyBundle { target_user_id } => {
            Some(prekey::handle_fetch(state, target_user_id).await)
        }
        ClientMessage::SendMessage {
            recipient_id,
            message_id,
            envelope,
        } => {
            let sender_id = session.authed_user.as_ref()?;
            Some(message::handle_send(state, sender_id, recipient_id, message_id, envelope).await)
        }
        ClientMessage::Ack {
            ack_id,
            message_ids,
        } => {
            let user_id = session.authed_user.as_ref()?;
            message::handle_ack(state, user_id, ack_id, message_ids).await
        }
        ClientMessage::Typing { recipient_id } => {
            let sender_id = session.authed_user.as_ref()?;
            message::handle_typing(state, sender_id, &recipient_id);
            None
        }
        ClientMessage::SendReadReceipt {
            recipient_id,
            receipt_id,
            envelope,
        } => {
            let sender_id = session.authed_user.as_ref()?;
            message::handle_read_receipt(state, sender_id, &recipient_id, receipt_id, &envelope)
                .await
        }
        ClientMessage::AckReadReceipt {
            ack_id,
            receipt_ids,
        } => {
            let user_id = session.authed_user.as_ref()?;
            Some(message::handle_read_receipt_ack(state, user_id, ack_id, receipt_ids).await)
        }
        ClientMessage::AckReadReceiptSent { receipt_ids } => {
            let user_id = session.authed_user.as_ref()?;
            Some(message::handle_read_receipt_sent_ack(state, user_id, receipt_ids).await)
        }
        _ => {
            warn!("unhandled message type");
            Some(error_400("unhandled message type"))
        }
    }
}

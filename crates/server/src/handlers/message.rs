use base64::{Engine, engine::general_purpose::STANDARD as B64};
use protocol::{
    EncryptedEnvelope, InboundMessage, MessageId, ServerMessage, UserId, consts,
    types::MessageHeader,
};

use super::{error_400, error_500_generic, now_secs};
use crate::db;
use crate::db::queue::EnqueueResult;
use crate::state::AppState;

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn handle_send(
    state: &AppState,
    sender_id: &str,
    recipient_id: UserId,
    message_id: MessageId,
    envelope: EncryptedEnvelope,
) -> ServerMessage {
    if let Err(message) = validate_envelope(&envelope) {
        return error_400(message);
    }

    let msg_id_str = message_id.to_string();
    let recipient_str = recipient_id.as_str();

    let Ok(sender_user_id) = UserId::new(sender_id) else {
        return error_500_generic();
    };
    let inbound = InboundMessage {
        message_id: message_id.clone(),
        sender_id: sender_user_id,
        envelope: envelope.clone(),
        timestamp: now_secs(),
    };
    let Ok(queued_page) = serde_json::to_vec(&ServerMessage::QueuedMessages {
        messages: vec![inbound.clone()],
    }) else {
        return error_400("invalid envelope");
    };
    if queued_page.len() > consts::MAX_QUEUED_PAGE_BYTES {
        return error_400("message exceeds queued delivery size");
    }

    let Ok(envelope_json) = serde_json::to_string(&envelope) else {
        return error_400("invalid envelope");
    };

    match db::queue::enqueue(
        &state.db,
        &msg_id_str,
        recipient_str,
        sender_id,
        envelope_json,
        consts::MAX_QUEUE_PER_USER,
    )
    .await
    {
        Ok(EnqueueResult::Inserted | EnqueueResult::Duplicate) => {}
        Ok(EnqueueResult::QueueFull) => {
            return error_400("recipient's message queue is full");
        }
        Ok(EnqueueResult::RecipientNotFound) => {
            return super::error_404("not found");
        }
        Err(e) => {
            tracing::error!("failed to queue message: {e}");
            return error_500_generic();
        }
    }

    // Push to recipient if online
    let pushed = state
        .connections
        .send_to(recipient_str, ServerMessage::IncomingMessage(inbound));

    // Server-generated delivery receipt: if the message was pushed to the
    // recipient's device, notify the sender immediately.
    if pushed {
        state.connections.send_to(
            sender_id,
            ServerMessage::MessageDelivered {
                message_ids: vec![message_id.clone()],
            },
        );
    }

    ServerMessage::MessageSent { message_id }
}

/// Delete acknowledged messages — scoped to the authenticated user's own queue.
#[allow(clippy::cognitive_complexity)]
pub(crate) async fn handle_ack(
    state: &AppState,
    recipient_id: &str,
    message_ids: Vec<MessageId>,
) -> Option<ServerMessage> {
    if message_ids.len() > consts::MAX_ACK_BATCH {
        tracing::warn!(
            recipient_id,
            count = message_ids.len(),
            "ack batch too large"
        );
        return Some(error_400("ack batch exceeds maximum size"));
    }

    let ids: Vec<String> = message_ids.iter().map(ToString::to_string).collect();
    if let Err(e) = db::queue::delete_messages(&state.db, recipient_id, &ids).await {
        tracing::warn!(recipient_id, "ack delete failed: {e}");
        return Some(error_500_generic());
    }
    Some(ServerMessage::AckSuccess { message_ids })
}

/// Relay a typing indicator — online only, never queued.
// TODO: add per-connection rate limiting to prevent flooding
pub(crate) fn handle_typing(state: &AppState, from: &str, to: &UserId) {
    let Ok(from_uid) = UserId::new(from) else {
        return;
    };
    state.connections.send_to(
        to.as_str(),
        ServerMessage::PeerTyping {
            sender_id: from_uid,
        },
    );
}

/// Relay an E2EE read receipt — online only, never queued.
pub(crate) fn handle_read_receipt(
    state: &AppState,
    from: &str,
    to: &UserId,
    receipt_id: MessageId,
    envelope: &protocol::EncryptedEnvelope,
) -> Option<ServerMessage> {
    if let Err(message) = validate_envelope(envelope) {
        return Some(error_400(message));
    }
    let Ok(from_uid) = UserId::new(from) else {
        return None;
    };
    let delivered = state.connections.send_to(
        to.as_str(),
        ServerMessage::IncomingReadReceipt {
            sender_id: from_uid,
            envelope: envelope.clone(),
        },
    );
    if delivered {
        Some(ServerMessage::ReadReceiptSent { receipt_id })
    } else {
        Some(error_400("recipient is not available"))
    }
}

pub(crate) fn validate_envelope(envelope: &EncryptedEnvelope) -> Result<(), &'static str> {
    if envelope.ciphertext.len() > consts::MAX_CIPHERTEXT_BYTES {
        return Err("ciphertext exceeds maximum size");
    }
    if B64.decode(&envelope.ciphertext).is_err() {
        return Err("invalid ciphertext encoding");
    }

    match &envelope.header {
        MessageHeader::PreKey {
            sender_identity_key,
            sender_ephemeral_key,
            ratchet,
            ..
        } => {
            validate_b64_len::<32>(sender_identity_key)?;
            validate_b64_len::<32>(sender_ephemeral_key)?;
            validate_b64_len::<32>(&ratchet.ratchet_key)?;
        }
        MessageHeader::Ratchet(ratchet) => validate_b64_len::<32>(&ratchet.ratchet_key)?,
        _ => return Err("unsupported message header"),
    }
    Ok(())
}

fn validate_b64_len<const N: usize>(encoded: &str) -> Result<(), &'static str> {
    let decoded = B64.decode(encoded).map_err(|_| "invalid key encoding")?;
    if decoded.len() != N {
        return Err("invalid key length");
    }
    Ok(())
}

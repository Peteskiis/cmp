use std::time::{SystemTime, UNIX_EPOCH};

use protocol::{EncryptedEnvelope, InboundMessage, MessageId, ServerMessage, UserId, consts};

use super::{error_400, error_500_generic};
use crate::db;
use crate::db::queue::EnqueueResult;
use crate::state::AppState;

#[allow(clippy::cognitive_complexity)]
pub async fn handle_send(
    state: &AppState,
    sender_id: &str,
    recipient_id: UserId,
    message_id: MessageId,
    envelope: EncryptedEnvelope,
) -> ServerMessage {
    if envelope.ciphertext.len() > consts::MAX_CIPHERTEXT_BYTES {
        return error_400("ciphertext exceeds maximum size");
    }

    let msg_id_str = message_id.to_string();
    let recipient_str = recipient_id.as_str();

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
    let Ok(sender_user_id) = UserId::new(sender_id) else {
        return ServerMessage::MessageSent {
            message_id: message_id.clone(),
        };
    };

    let inbound = InboundMessage {
        message_id: message_id.clone(),
        sender_id: sender_user_id,
        envelope,
        timestamp: now_secs(),
    };
    state
        .connections
        .send_to(recipient_str, ServerMessage::IncomingMessage(inbound));

    ServerMessage::MessageSent { message_id }
}

/// Delete acknowledged messages — scoped to the authenticated user's own queue.
#[allow(clippy::cognitive_complexity)]
pub async fn handle_ack(
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
    }
    None
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

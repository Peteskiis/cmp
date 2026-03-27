use protocol::{EncryptedEnvelope, InboundMessage, MessageId, ServerMessage, UserId, consts};

use super::{error_400, error_500_generic};
use crate::db;
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

    let envelope_json = match serde_json::to_string(&envelope) {
        Ok(j) => j,
        Err(e) => return error_400(&format!("invalid envelope: {e}")),
    };

    // Enqueue directly — FK constraint on recipient_id catches non-existent users.
    // Avoids TOCTOU race and extra DB round-trip vs a separate exists() check.
    match db::queue::enqueue(
        &state.db,
        &msg_id_str,
        recipient_str,
        sender_id,
        envelope_json,
    )
    .await
    {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string();
            return if msg.contains("FOREIGN KEY") {
                error_400("recipient not found")
            } else {
                {
                    tracing::error!("failed to queue message: {e}");
                    error_500_generic()
                }
            };
        }
    }

    // Push to recipient if online — try_send handles offline/full channel
    let Ok(sender_user_id) = UserId::new(sender_id) else {
        return ServerMessage::MessageSent {
            message_id: message_id.clone(),
        };
    };

    let inbound = InboundMessage {
        message_id: message_id.clone(),
        sender_id: sender_user_id,
        envelope,
        timestamp: 0,
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

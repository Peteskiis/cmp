use base64::{Engine, engine::general_purpose::STANDARD as B64};
use protocol::{
    EncryptedEnvelope, InboundMessage, MessageId, ServerMessage, UserId, consts,
    types::MessageHeader,
};

use super::{error_400, error_500_generic, now_secs};
use crate::db;
use crate::db::queue::{EnqueueRequest, EnqueueResult};
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
    let (signed_prekey_id, one_time_prekey_id) = envelope_prekey_ids(&envelope.header);

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

    let enqueue_result = db::queue::enqueue(
        &state.db,
        EnqueueRequest {
            message_id: msg_id_str,
            recipient_id: recipient_str.to_owned(),
            sender_id: sender_id.to_owned(),
            envelope_json,
            max_queue_per_user: consts::MAX_QUEUE_PER_USER,
            signed_prekey_id,
            one_time_prekey_id,
            now: now_secs(),
        },
    )
    .await;
    if let Err(response) = validate_enqueue_result(enqueue_result, &message_id) {
        return response;
    }

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

#[allow(clippy::result_large_err)]
fn validate_enqueue_result(
    result: anyhow::Result<EnqueueResult>,
    message_id: &MessageId,
) -> Result<(), ServerMessage> {
    match result {
        Ok(EnqueueResult::Inserted | EnqueueResult::Duplicate) => Ok(()),
        Ok(EnqueueResult::QueueFull) => Err(error_400("recipient's message queue is full")),
        Ok(EnqueueResult::RecipientNotFound) => Err(super::error_404("not found")),
        Ok(EnqueueResult::PrekeyReservationInvalid) => Err(ServerMessage::MessageRejected {
            message_id: message_id.clone(),
            reason: "one-time pre-key reservation expired".to_owned(),
        }),
        Ok(EnqueueResult::SignedPrekeyExpired) => Err(ServerMessage::MessageRejected {
            message_id: message_id.clone(),
            reason: "signed pre-key expired".to_owned(),
        }),
        Ok(EnqueueResult::MessageIdConflict) => {
            Err(error_400("message ID already used with different content"))
        }
        Ok(EnqueueResult::AcceptanceLedgerFull) => {
            Err(error_400("too many unconfirmed sent messages"))
        }
        Err(error) => {
            tracing::error!("failed to queue message: {error}");
            Err(error_500_generic())
        }
    }
}

pub(crate) async fn handle_message_sent_ack(
    state: &AppState,
    sender_id: &str,
    message_ids: Vec<MessageId>,
) -> Option<ServerMessage> {
    if message_ids.len() > consts::MAX_ACK_BATCH {
        return Some(error_400("ack batch exceeds maximum size"));
    }
    let ids: Vec<String> = message_ids.iter().map(ToString::to_string).collect();
    if let Err(error) = db::queue::confirm_acceptances(&state.db, sender_id, &ids).await {
        tracing::error!("failed to confirm message acceptance: {error}");
        return Some(error_500_generic());
    }
    None
}

const fn envelope_prekey_ids(header: &MessageHeader) -> (Option<u32>, Option<u32>) {
    match header {
        MessageHeader::PreKey {
            recipient_signed_prekey_id,
            recipient_one_time_prekey_id,
            ..
        } => (
            Some(*recipient_signed_prekey_id),
            *recipient_one_time_prekey_id,
        ),
        _ => (None, None),
    }
}

/// Delete acknowledged messages — scoped to the authenticated user's own queue.
#[allow(clippy::cognitive_complexity)]
pub(crate) async fn handle_ack(
    state: &AppState,
    recipient_id: &str,
    ack_id: MessageId,
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
    Some(ServerMessage::AckSuccess {
        ack_id,
        message_ids,
    })
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

/// Durably relay an E2EE read receipt and confirm it only after recipient ACK.
pub(crate) async fn handle_read_receipt(
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
    let Ok(envelope_json) = serde_json::to_string(envelope) else {
        return Some(error_400("invalid envelope"));
    };
    let enqueue_result = db::receipts::enqueue(
        &state.db,
        &receipt_id.to_string(),
        to.as_str(),
        from,
        envelope_json,
        consts::MAX_QUEUE_PER_USER,
    )
    .await;
    match enqueue_result {
        Ok(db::receipts::EnqueueResult::Inserted | db::receipts::EnqueueResult::Duplicate) => {}
        Ok(db::receipts::EnqueueResult::AlreadyAcknowledged) => {
            return Some(ServerMessage::ReadReceiptSent { receipt_id });
        }
        Ok(db::receipts::EnqueueResult::QueueFull) => {
            return Some(error_400("recipient read receipt queue is full"));
        }
        Ok(db::receipts::EnqueueResult::Collision) => {
            return Some(error_400("read receipt ID already exists"));
        }
        Err(error) => {
            tracing::error!("failed to queue read receipt: {error}");
            return Some(error_500_generic());
        }
    }
    state.connections.send_to(
        to.as_str(),
        ServerMessage::IncomingReadReceipt {
            sender_id: from_uid,
            receipt_id,
            envelope: envelope.clone(),
        },
    );
    None
}

pub(crate) async fn handle_read_receipt_sent_ack(
    state: &AppState,
    sender_id: &str,
    receipt_ids: Vec<MessageId>,
) -> ServerMessage {
    if receipt_ids.len() > consts::MAX_RECEIPT_BATCH {
        return error_400("read receipt confirmation exceeds maximum size");
    }
    let ids: Vec<String> = receipt_ids.iter().map(ToString::to_string).collect();
    if let Err(error) = db::receipts::confirm_sender_received(&state.db, sender_id, &ids).await {
        tracing::error!("failed to confirm read receipt notifications: {error}");
        return error_500_generic();
    }
    ServerMessage::Success
}

pub(crate) async fn handle_read_receipt_ack(
    state: &AppState,
    recipient_id: &str,
    ack_id: MessageId,
    receipt_ids: Vec<MessageId>,
) -> ServerMessage {
    if receipt_ids.len() > consts::MAX_RECEIPT_BATCH {
        return error_400("read receipt ack exceeds maximum size");
    }
    let ids: Vec<String> = receipt_ids.iter().map(ToString::to_string).collect();
    let acknowledged = match db::receipts::acknowledge(&state.db, recipient_id, &ids).await {
        Ok(acknowledged) => acknowledged,
        Err(error) => {
            tracing::error!("failed to acknowledge read receipts: {error}");
            return error_500_generic();
        }
    };
    notify_receipt_senders(state, acknowledged);
    ServerMessage::AckSuccess {
        ack_id,
        message_ids: receipt_ids,
    }
}

fn notify_receipt_senders(state: &AppState, acknowledged: Vec<(String, String)>) {
    for (receipt_id, sender_id) in acknowledged {
        if let Ok(receipt_id) = uuid::Uuid::parse_str(&receipt_id) {
            state.connections.send_to(
                &sender_id,
                ServerMessage::ReadReceiptSent {
                    receipt_id: receipt_id.into(),
                },
            );
        }
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

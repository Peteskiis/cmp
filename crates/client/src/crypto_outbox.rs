use protocol::{ClientMessage, EncryptedEnvelope, MessageId, OneTimePreKey, UserId, consts};
use serde::{Deserialize, Serialize};

use crate::crypto_mgr::CryptoError;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(super) enum PendingOutbound {
    Message {
        recipient_id: UserId,
        message_id: MessageId,
        envelope: EncryptedEnvelope,
    },
    ReadReceipt {
        recipient_id: UserId,
        receipt_id: MessageId,
        envelope: EncryptedEnvelope,
    },
    Ack {
        ack_id: MessageId,
        message_ids: Vec<MessageId>,
    },
    ReadReceiptAck {
        ack_id: MessageId,
        receipt_ids: Vec<MessageId>,
    },
    PreKeyUpload {
        upload_id: MessageId,
        prekeys: Vec<OneTimePreKey>,
    },
}

impl PendingOutbound {
    pub(super) fn to_client_message(&self) -> ClientMessage {
        match self {
            Self::Message {
                recipient_id,
                message_id,
                envelope,
                ..
            } => ClientMessage::SendMessage {
                recipient_id: recipient_id.clone(),
                message_id: message_id.clone(),
                envelope: envelope.clone(),
            },
            Self::ReadReceipt {
                recipient_id,
                receipt_id,
                envelope,
            } => ClientMessage::SendReadReceipt {
                recipient_id: recipient_id.clone(),
                receipt_id: receipt_id.clone(),
                envelope: envelope.clone(),
            },
            Self::Ack {
                ack_id,
                message_ids,
            } => ClientMessage::Ack {
                ack_id: ack_id.clone(),
                message_ids: message_ids.clone(),
            },
            Self::ReadReceiptAck {
                ack_id,
                receipt_ids,
            } => ClientMessage::AckReadReceipt {
                ack_id: ack_id.clone(),
                receipt_ids: receipt_ids.clone(),
            },
            Self::PreKeyUpload { upload_id, prekeys } => ClientMessage::UploadPreKeys {
                upload_id: upload_id.clone(),
                prekeys: prekeys.clone(),
            },
        }
    }

    const fn ciphertext_len(&self) -> usize {
        match self {
            Self::Message { envelope, .. } | Self::ReadReceipt { envelope, .. } => {
                envelope.ciphertext.len()
            }
            Self::Ack { message_ids, .. } => message_ids.len() * 36,
            Self::ReadReceiptAck { receipt_ids, .. } => receipt_ids.len() * 36,
            Self::PreKeyUpload { prekeys, .. } => prekeys.len() * 48,
        }
    }

    pub(super) fn correlation_id(&self) -> String {
        match self {
            Self::Message { message_id, .. } => message_id.to_string(),
            Self::ReadReceipt { receipt_id, .. } => receipt_id.to_string(),
            Self::Ack { ack_id, .. } | Self::ReadReceiptAck { ack_id, .. } => ack_id.to_string(),
            Self::PreKeyUpload { upload_id, .. } => upload_id.to_string(),
        }
    }
}

pub(super) fn ensure_capacity(
    pending: &[PendingOutbound],
    additional_plaintext_bytes: usize,
) -> Result<(), CryptoError> {
    if pending.len() >= consts::MAX_PENDING_OUTBOUND_ITEMS {
        return Err(CryptoError::OutboxFull);
    }
    let current_bytes: usize = pending.iter().map(PendingOutbound::ciphertext_len).sum();
    let additional_bytes = (additional_plaintext_bytes + 18) / 3 * 4;
    if current_bytes.saturating_add(additional_bytes) > consts::MAX_PENDING_OUTBOUND_BYTES {
        return Err(CryptoError::OutboxFull);
    }
    Ok(())
}

use protocol::{ClientMessage, EncryptedEnvelope, MessageId, UserId, consts};
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
}

impl PendingOutbound {
    pub(super) fn to_client_message(&self) -> ClientMessage {
        match self {
            Self::Message {
                recipient_id,
                message_id,
                envelope,
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
        }
    }

    const fn ciphertext_len(&self) -> usize {
        match self {
            Self::Message { envelope, .. } | Self::ReadReceipt { envelope, .. } => {
                envelope.ciphertext.len()
            }
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

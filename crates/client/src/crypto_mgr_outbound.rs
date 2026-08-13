use super::{
    ClientMessage, CryptoManager, EncryptedEnvelope, HashSet, MessageHeader, MessageId,
    PendingOutbound, UserId, now_secs, restore_entry,
};

impl CryptoManager {
    pub(crate) fn pending_messages(&self) -> Vec<ClientMessage> {
        self.pending_outbound
            .iter()
            .map(PendingOutbound::to_client_message)
            .collect()
    }

    pub(super) fn retire_stale_prekey_outbox(&mut self) -> anyhow::Result<()> {
        let now = now_secs();
        let recipients: HashSet<String> = self
            .pending_outbound
            .iter()
            .filter_map(|pending| match pending {
                PendingOutbound::Message {
                    recipient_id,
                    envelope:
                        EncryptedEnvelope {
                            header: MessageHeader::PreKey { .. },
                            ..
                        },
                    prekey_expires_at,
                    ..
                } if prekey_expires_at.is_none_or(|expires_at| expires_at < now) => {
                    Some(recipient_id.as_str().to_owned())
                }
                _ => None,
            })
            .collect();
        if recipients.is_empty() {
            return Ok(());
        }

        let retired_ids: Vec<String> = self
            .pending_outbound
            .iter()
            .filter_map(|pending| match pending {
                PendingOutbound::Message {
                    recipient_id,
                    message_id,
                    ..
                } if recipients.contains(recipient_id.as_str()) => Some(message_id.to_string()),
                _ => None,
            })
            .collect();
        self.pending_outbound.retain(|pending| {
            !matches!(
                pending,
                PendingOutbound::Message { recipient_id, .. }
                    if recipients.contains(recipient_id.as_str())
            )
        });
        for recipient in &recipients {
            self.sessions.remove(recipient);
            self.pending_inits.insert(recipient.clone());
        }
        self.store
            .save_core_and_delete_outbound_batch(&self.core_state(), &retired_ids)
    }

    pub(crate) fn confirm_message_sent(&mut self, message_id: &MessageId) -> anyhow::Result<()> {
        let Some(index) = self.pending_outbound.iter().position(|pending| {
            matches!(
                pending,
                PendingOutbound::Message { message_id: pending_id, .. }
                    if pending_id == message_id
            )
        }) else {
            return Ok(());
        };
        let pending = self.pending_outbound.remove(index);
        if let Err(error) = self.store.delete_outbound(&message_id.to_string()) {
            self.pending_outbound.insert(index, pending);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn reject_message(
        &mut self,
        message_id: &MessageId,
    ) -> anyhow::Result<Option<UserId>> {
        let Some(index) = self.pending_outbound.iter().position(|pending| {
            matches!(
                pending,
                PendingOutbound::Message { message_id: pending_id, .. }
                    if pending_id == message_id
            )
        }) else {
            return Ok(None);
        };
        let PendingOutbound::Message { recipient_id, .. } = &self.pending_outbound[index] else {
            return Ok(None);
        };
        let recipient_id = recipient_id.clone();
        self.check_persistence()?;
        let previous_session = self.sessions.remove(recipient_id.as_str());
        let pending = self.pending_outbound.remove(index);
        if let Err(error) = self
            .store
            .save_core_and_delete_outbound(&self.core_state(), &message_id.to_string())
        {
            restore_entry(&mut self.sessions, recipient_id.as_str(), previous_session);
            self.pending_outbound.insert(index, pending);
            return Err(error);
        }
        Ok(Some(recipient_id))
    }
}

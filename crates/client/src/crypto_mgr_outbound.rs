use super::{ClientMessage, CryptoManager, MessageId, PendingOutbound, UserId, restore_entry};

impl CryptoManager {
    pub(crate) fn pending_messages(&self) -> Vec<ClientMessage> {
        self.pending_outbound
            .iter()
            .map(PendingOutbound::to_client_message)
            .collect()
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

use base64::Engine;
use crypto::keys::{OneTimePreKey, SignedPreKey};
use protocol::{ClientMessage, MessageId};

use super::{B64, CryptoError, CryptoManager, PendingOutbound, ensure_capacity};

impl CryptoManager {
    /// Store SPK and OPK private keys after registration.
    pub(crate) fn persist_registration_keys(
        &mut self,
        spk: &SignedPreKey,
        opks: &[OneTimePreKey],
    ) -> anyhow::Result<()> {
        let new_spk = SignedPreKey::from_parts(
            spk.key_id(),
            spk.secret().to_bytes(),
            spk.public().to_bytes(),
            *spk.signature(),
        );
        let new_opks = opks
            .iter()
            .map(|opk| {
                (
                    opk.key_id(),
                    OneTimePreKey::from_parts(
                        opk.key_id(),
                        opk.secret().to_bytes(),
                        opk.public().to_bytes(),
                    ),
                )
            })
            .collect();

        let previous_spk = self.stored_spk.replace(new_spk);
        let previous_opks = std::mem::replace(&mut self.stored_opks, new_opks);
        let previous_next_id = self.next_one_time_prekey_id;
        self.next_one_time_prekey_id = opks
            .iter()
            .map(OneTimePreKey::key_id)
            .max()
            .map_or(previous_next_id, |key_id| key_id.saturating_add(1));
        if let Err(error) = self.persist_state() {
            self.stored_spk = previous_spk;
            self.stored_opks = previous_opks;
            self.next_one_time_prekey_id = previous_next_id;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn confirm_prekeys_uploaded(
        &mut self,
        upload_id: &MessageId,
        accepted: bool,
    ) -> anyhow::Result<()> {
        let Some(index) = self.pending_outbound.iter().position(|pending| {
            matches!(
                pending,
                PendingOutbound::PreKeyUpload { upload_id: pending_id, .. }
                    if pending_id == upload_id
            )
        }) else {
            return Ok(());
        };
        let pending = self.pending_outbound.remove(index);
        let removed_keys: Vec<_> = if accepted {
            Vec::new()
        } else {
            let PendingOutbound::PreKeyUpload { prekeys, .. } = &pending else {
                return Ok(());
            };
            prekeys
                .iter()
                .filter_map(|prekey| {
                    self.stored_opks
                        .remove(&prekey.key_id)
                        .map(|key| (prekey.key_id, key))
                })
                .collect()
        };
        let result = if accepted {
            self.store.delete_outbound(&upload_id.to_string())
        } else {
            self.store
                .save_core_and_delete_outbound(&self.core_state(), &upload_id.to_string())
        };
        if let Err(error) = result {
            self.stored_opks.extend(removed_keys);
            self.pending_outbound.insert(index, pending);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn queue_prekey_replenishment(&mut self) -> Result<ClientMessage, CryptoError> {
        if let Some(pending) = self
            .pending_outbound
            .iter()
            .find(|pending| matches!(pending, PendingOutbound::PreKeyUpload { .. }))
        {
            return Ok(pending.to_client_message());
        }

        let count = u32::try_from(protocol::consts::PREKEY_TARGET)
            .map_err(|_| CryptoError::RatchetFailed)?;
        let generated =
            crypto::keys::generate_one_time_prekeys(self.next_one_time_prekey_id, count)
                .map_err(|_| CryptoError::RatchetFailed)?;
        let prekeys: Vec<protocol::OneTimePreKey> = generated
            .iter()
            .map(|prekey| protocol::OneTimePreKey {
                key_id: prekey.key_id(),
                public_key: B64.encode(prekey.public().as_bytes()),
            })
            .collect();
        ensure_capacity(&self.pending_outbound, prekeys.len() * 48)?;

        let previous_next_id = self.next_one_time_prekey_id;
        self.next_one_time_prekey_id = previous_next_id
            .checked_add(count)
            .ok_or(CryptoError::RatchetFailed)?;
        let generated_ids: Vec<u32> = generated.iter().map(OneTimePreKey::key_id).collect();
        self.stored_opks.extend(
            generated
                .into_iter()
                .map(|prekey| (prekey.key_id(), prekey)),
        );
        let pending = PendingOutbound::PreKeyUpload {
            upload_id: MessageId::new(),
            prekeys,
        };
        self.pending_outbound.push(pending.clone());
        if let Err(error) = self.persist_outbound(&pending) {
            for key_id in generated_ids {
                self.stored_opks.remove(&key_id);
            }
            self.next_one_time_prekey_id = previous_next_id;
            self.pending_outbound.pop();
            return Err(CryptoError::Persistence(error));
        }
        Ok(pending.to_client_message())
    }
}

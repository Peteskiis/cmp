use base64::Engine;
use crypto::keys::{OneTimePreKey, SignedPreKey};
use protocol::{ClientMessage, MessageId};

use super::{B64, CryptoError, CryptoManager, PendingOutbound, ensure_capacity};

impl CryptoManager {
    pub(super) fn take_one_time_prekey(
        &mut self,
        key_id: u32,
    ) -> Option<(OneTimePreKey, Option<u64>)> {
        self.stored_opks.remove(&key_id).map(|prekey| {
            let created_at = self.one_time_prekey_created_at.remove(&key_id);
            (prekey, created_at)
        })
    }

    pub(super) fn restore_one_time_prekey(
        &mut self,
        key_id: u32,
        prekey: OneTimePreKey,
        created_at: Option<u64>,
    ) {
        self.stored_opks.insert(key_id, prekey);
        self.one_time_prekey_created_at
            .extend(created_at.map(|timestamp| (key_id, timestamp)));
    }

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
        let previous_created_at = std::mem::take(&mut self.one_time_prekey_created_at);
        let created_at = crate::crypto_replay::now_secs();
        self.one_time_prekey_created_at =
            opks.iter().map(|opk| (opk.key_id(), created_at)).collect();
        self.next_one_time_prekey_id = opks
            .iter()
            .map(OneTimePreKey::key_id)
            .max()
            .map_or(previous_next_id, |key_id| key_id.saturating_add(1));
        if let Err(error) = self.persist_state() {
            self.stored_spk = previous_spk;
            self.stored_opks = previous_opks;
            self.next_one_time_prekey_id = previous_next_id;
            self.one_time_prekey_created_at = previous_created_at;
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
        let removed_created_at: Vec<_> = removed_keys
            .iter()
            .filter_map(|(key_id, _)| {
                self.one_time_prekey_created_at
                    .remove(key_id)
                    .map(|created_at| (*key_id, created_at))
            })
            .collect();
        let result = if accepted {
            self.store.delete_outbound(&upload_id.to_string())
        } else {
            self.store
                .save_core_and_delete_outbound(&self.core_state(), &upload_id.to_string())
        };
        if let Err(error) = result {
            self.stored_opks.extend(removed_keys);
            self.one_time_prekey_created_at.extend(removed_created_at);
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

        let cutoff =
            crate::crypto_replay::now_secs().saturating_sub(crate::crypto_replay::RETENTION_SECS);
        let stale_ids: Vec<_> = self
            .one_time_prekey_created_at
            .iter()
            .filter_map(|(key_id, created_at)| (*created_at < cutoff).then_some(*key_id))
            .collect();
        let stale_keys: Vec<_> = stale_ids
            .iter()
            .filter_map(|key_id| self.stored_opks.remove(key_id).map(|key| (*key_id, key)))
            .collect();
        let stale_created_at: Vec<_> = stale_ids
            .iter()
            .filter_map(|key_id| {
                self.one_time_prekey_created_at
                    .remove(key_id)
                    .map(|created_at| (*key_id, created_at))
            })
            .collect();

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
        let created_at = crate::crypto_replay::now_secs();
        self.one_time_prekey_created_at
            .extend(generated_ids.iter().map(|key_id| (*key_id, created_at)));
        let pending = PendingOutbound::PreKeyUpload {
            upload_id: MessageId::new(),
            prekeys,
        };
        self.pending_outbound.push(pending.clone());
        if let Err(error) = self.persist_outbound(&pending) {
            for key_id in generated_ids {
                self.stored_opks.remove(&key_id);
                self.one_time_prekey_created_at.remove(&key_id);
            }
            self.next_one_time_prekey_id = previous_next_id;
            self.pending_outbound.pop();
            self.stored_opks.extend(stale_keys);
            self.one_time_prekey_created_at.extend(stale_created_at);
            return Err(CryptoError::Persistence(error));
        }
        Ok(pending.to_client_message())
    }
}

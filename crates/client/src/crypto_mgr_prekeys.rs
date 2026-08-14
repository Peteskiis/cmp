use base64::Engine;
use crypto::keys::{OneTimePreKey, SignedPreKey};
use protocol::{ClientMessage, MessageId};

use super::{B64, CryptoError, CryptoManager, PendingOutbound, ensure_capacity};

const SIGNED_PREKEY_PRIVATE_HISTORY: usize = 3;

impl CryptoManager {
    #[cfg(test)]
    pub(crate) const fn force_signed_prekey_rotation_due(&mut self) {
        self.signed_prekey_rotated_at = 0;
    }

    pub(crate) fn expire_stale_prekey_session(
        &mut self,
        peer_id: &str,
    ) -> Result<bool, CryptoError> {
        let stale = self.sessions.get(peer_id).is_some_and(|session| {
            session.prekey_header.is_some()
                && session
                    .prekey_expires_at
                    .is_some_and(|expires_at| expires_at < crate::crypto_replay::now_secs())
        });
        if !stale {
            return Ok(false);
        }
        let previous = self.sessions.remove(peer_id);
        if let Err(error) = self.persist_state() {
            if let Some(session) = previous {
                self.sessions.insert(peer_id.to_owned(), session);
            }
            return Err(CryptoError::Persistence(error));
        }
        Ok(true)
    }

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
        let previous_previous_spks = std::mem::take(&mut self.previous_spks);
        let previous_rotated_at = self.signed_prekey_rotated_at;
        let previous_next_signed_prekey_id = self.next_signed_prekey_id;
        self.signed_prekey_rotated_at = crate::crypto_replay::now_secs();
        self.next_signed_prekey_id = spk.key_id().saturating_add(1);
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
        self.next_one_time_prekey_id = self.next_one_time_prekey_id.max(previous_next_id);
        if let Err(error) = self.persist_state() {
            self.stored_spk = previous_spk;
            self.previous_spks = previous_previous_spks;
            self.signed_prekey_rotated_at = previous_rotated_at;
            self.next_signed_prekey_id = previous_next_signed_prekey_id;
            self.stored_opks = previous_opks;
            self.next_one_time_prekey_id = previous_next_id;
            self.one_time_prekey_created_at = previous_created_at;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn queue_signed_prekey_rotation(&mut self) -> Result<bool, CryptoError> {
        if self
            .pending_outbound
            .iter()
            .any(|pending| matches!(pending, PendingOutbound::SignedPreKeyRotation { .. }))
        {
            return Ok(false);
        }
        let now = crate::crypto_replay::now_secs();
        if self.signed_prekey_rotated_at != 0
            && now.saturating_sub(self.signed_prekey_rotated_at)
                < protocol::consts::SIGNED_PREKEY_ROTATION_SECS
        {
            return Ok(false);
        }
        let current_id = self
            .stored_spk
            .as_ref()
            .ok_or(CryptoError::NoSession)?
            .key_id();
        let key_id = self.next_signed_prekey_id.max(
            current_id
                .checked_add(1)
                .ok_or(CryptoError::RatchetFailed)?,
        );
        let next_key_id = key_id.checked_add(1).ok_or(CryptoError::RatchetFailed)?;
        ensure_capacity(&self.pending_outbound, 96)?;
        let new_spk = SignedPreKey::generate(key_id, &self.identity);
        let pending = PendingOutbound::SignedPreKeyRotation {
            rotation_id: MessageId::new(),
            key_id,
            public_key: B64.encode(new_spk.public().as_bytes()),
            signature: B64.encode(new_spk.signature().to_bytes()),
            previous_rotated_at: self.signed_prekey_rotated_at,
        };

        let previous_current = self.stored_spk.replace(new_spk);
        if let Some(previous) = previous_current {
            self.previous_spks.insert(0, previous);
        }
        let previous_rotated_at = self.signed_prekey_rotated_at;
        let previous_next_signed_prekey_id = self.next_signed_prekey_id;
        self.signed_prekey_rotated_at = now;
        self.next_signed_prekey_id = next_key_id;
        self.pending_outbound.push(pending.clone());
        if let Err(error) = self.persist_outbound(&pending) {
            self.pending_outbound.pop();
            self.stored_spk = if self.previous_spks.is_empty() {
                None
            } else {
                Some(self.previous_spks.remove(0))
            };
            self.signed_prekey_rotated_at = previous_rotated_at;
            self.next_signed_prekey_id = previous_next_signed_prekey_id;
            return Err(CryptoError::Persistence(error));
        }
        Ok(true)
    }

    pub(crate) fn confirm_signed_prekey_rotated(
        &mut self,
        rotation_id: &MessageId,
        accepted: bool,
        current_key_id: u32,
    ) -> anyhow::Result<Option<ClientMessage>> {
        let Some(index) = self.pending_outbound.iter().position(|pending| {
            matches!(
                pending,
                PendingOutbound::SignedPreKeyRotation { rotation_id: pending_id, .. }
                    if pending_id == rotation_id
            )
        }) else {
            return Ok(None);
        };
        let candidate_key_id = match &self.pending_outbound[index] {
            PendingOutbound::SignedPreKeyRotation { key_id, .. } => *key_id,
            _ => anyhow::bail!("signed prekey rotation missing"),
        };
        if accepted && candidate_key_id == current_key_id {
            self.confirm_accepted_signed_prekey_rotation(index, rotation_id)?;
            return Ok(None);
        }
        self.reconcile_rejected_signed_prekey_rotation(index, rotation_id, current_key_id)
            .map(Some)
    }

    fn confirm_accepted_signed_prekey_rotation(
        &mut self,
        index: usize,
        rotation_id: &MessageId,
    ) -> anyhow::Result<()> {
        self.check_persistence()?;
        let dropped = if self.previous_spks.len() > SIGNED_PREKEY_PRIVATE_HISTORY {
            self.previous_spks.split_off(SIGNED_PREKEY_PRIVATE_HISTORY)
        } else {
            Vec::new()
        };
        if let Err(error) = self
            .store
            .save_core_and_delete_outbound(&self.core_state(), &rotation_id.to_string())
        {
            self.previous_spks.extend(dropped);
            return Err(error);
        }
        self.pending_outbound.remove(index);
        Ok(())
    }

    fn reconcile_rejected_signed_prekey_rotation(
        &mut self,
        index: usize,
        rotation_id: &MessageId,
        current_key_id: u32,
    ) -> anyhow::Result<ClientMessage> {
        self.check_persistence()?;
        let PendingOutbound::SignedPreKeyRotation {
            previous_rotated_at,
            ..
        } = &self.pending_outbound[index]
        else {
            anyhow::bail!("signed prekey rotation missing");
        };
        let previous_rotated_at = *previous_rotated_at;
        let restored_key_id = self
            .previous_spks
            .first()
            .ok_or_else(|| anyhow::anyhow!("previous signed prekey missing"))?
            .key_id();
        let replacement_key_id = self
            .next_signed_prekey_id
            .max(restored_key_id.saturating_add(1))
            .max(
                current_key_id
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("signed prekey ID exhausted"))?,
            );
        let next_key_id = replacement_key_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("signed prekey ID exhausted"))?;
        let replacement_key = SignedPreKey::generate(replacement_key_id, &self.identity);
        let replacement = PendingOutbound::SignedPreKeyRotation {
            rotation_id: MessageId::new(),
            key_id: replacement_key_id,
            public_key: B64.encode(replacement_key.public().as_bytes()),
            signature: B64.encode(replacement_key.signature().to_bytes()),
            previous_rotated_at,
        };

        let rejected_candidate = self.stored_spk.replace(replacement_key);
        let rejected_rotated_at = self.signed_prekey_rotated_at;
        let previous_next_signed_prekey_id = self.next_signed_prekey_id;
        let rejected_pending = std::mem::replace(&mut self.pending_outbound[index], replacement);
        self.signed_prekey_rotated_at = crate::crypto_replay::now_secs();
        self.next_signed_prekey_id = next_key_id;
        let replacement = &self.pending_outbound[index];
        if let Err(error) = self.store.save_core_and_replace_outbound(
            &self.core_state(),
            &rotation_id.to_string(),
            &replacement.correlation_id(),
            replacement,
        ) {
            self.stored_spk = rejected_candidate;
            self.pending_outbound[index] = rejected_pending;
            self.signed_prekey_rotated_at = rejected_rotated_at;
            self.next_signed_prekey_id = previous_next_signed_prekey_id;
            return Err(error);
        }
        Ok(self.pending_outbound[index].to_client_message())
    }

    pub(crate) fn confirm_prekeys_uploaded(
        &mut self,
        upload_id: &MessageId,
        accepted: bool,
        remaining: u32,
    ) -> anyhow::Result<Option<ClientMessage>> {
        let Some(index) = self.pending_outbound.iter().position(|pending| {
            matches!(
                pending,
                PendingOutbound::PreKeyUpload { upload_id: pending_id, .. }
                    if pending_id == upload_id
            )
        }) else {
            return Ok(None);
        };
        let pending = self.pending_outbound.remove(index);
        let removed_keys: Vec<_> = if accepted {
            Vec::new()
        } else {
            let PendingOutbound::PreKeyUpload { prekeys, .. } = &pending else {
                return Ok(None);
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
        let replacement = if accepted
            && remaining < u32::try_from(protocol::consts::PREKEY_TARGET).unwrap_or(u32::MAX)
        {
            match self.queue_prekey_replenishment() {
                Ok(upload) => Some(upload),
                Err(error) => {
                    self.pending_outbound.insert(index, pending);
                    return Err(anyhow::anyhow!(error));
                }
            }
        } else {
            None
        };
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
        Ok(replacement)
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

        let cutoff = crate::crypto_replay::now_secs()
            .saturating_sub(protocol::consts::ONE_TIME_PREKEY_PRIVATE_RETENTION_SECS);
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

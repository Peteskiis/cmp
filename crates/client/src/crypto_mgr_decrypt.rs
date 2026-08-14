use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crypto::keys::RatchetKeyPair;
use crypto::ratchet::{self, RatchetHeader, SessionState};
use crypto::x3dh;
use ed25519_dalek::VerifyingKey;
use protocol::{EncryptedEnvelope, MessageHeader, MessageId, aad, consts};
use x25519_dalek::PublicKey as X25519PublicKey;

use super::{CryptoError, CryptoManager, InboundDecrypt, PeerSession};
use crate::crypto_decode::{b64_decode_fixed, decode_ratchet_header};
use crate::crypto_replay::{now_secs, prune_processed};

impl CryptoManager {
    #[allow(clippy::cognitive_complexity)]
    #[cfg(test)]
    pub(crate) fn decrypt(
        &mut self,
        peer_id: &str,
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_with_marker(peer_id, envelope, None)
    }

    #[allow(clippy::cognitive_complexity)]
    fn decrypt_with_marker(
        &mut self,
        peer_id: &str,
        envelope: &EncryptedEnvelope,
        processed_message_id: Option<&str>,
    ) -> Result<Vec<u8>, CryptoError> {
        if envelope.version != consts::PROTOCOL_VERSION {
            return Err(CryptoError::UnsupportedVersion(envelope.version));
        }
        self.check_persistence().map_err(CryptoError::Persistence)?;
        let now = now_secs();
        let cutoff = now.saturating_sub(crate::crypto_replay::RETENTION_SECS);
        self.store
            .prune_processed(cutoff)
            .map_err(CryptoError::Persistence)?;
        prune_processed(&mut self.processed_messages, now);
        if processed_message_id.is_some()
            && self
                .processed_messages
                .values()
                .map(HashMap::len)
                .sum::<usize>()
                >= consts::MAX_PROCESSED_MESSAGES
        {
            return Err(CryptoError::ReplayLedgerFull);
        }
        if matches!(&envelope.header, MessageHeader::PreKey { .. }) {
            return self.decrypt_prekey_envelope(peer_id, envelope, processed_message_id);
        }

        let MessageHeader::Ratchet(ratchet_header) = &envelope.header else {
            return Err(CryptoError::BadEnvelope);
        };
        let header = decode_ratchet_header(ratchet_header)?;
        let ciphertext = B64
            .decode(&envelope.ciphertext)
            .map_err(|_| CryptoError::BadEnvelope)?;
        let envelope_aad = aad::ratchet(envelope.version);
        self.decrypt_existing(
            peer_id,
            &header,
            &ciphertext,
            &envelope_aad,
            processed_message_id,
        )
    }

    fn decrypt_prekey_envelope(
        &mut self,
        peer_id: &str,
        envelope: &EncryptedEnvelope,
        processed_message_id: Option<&str>,
    ) -> Result<Vec<u8>, CryptoError> {
        let MessageHeader::PreKey {
            sender_identity_key,
            sender_ephemeral_key,
            recipient_signed_prekey_id,
            recipient_one_time_prekey_id,
            ratchet,
            ..
        } = &envelope.header
        else {
            return Err(CryptoError::BadEnvelope);
        };
        // Parse header + ciphertext before session creation so parsing failures
        // cannot leave an orphan session in the map.
        let header = decode_ratchet_header(ratchet)?;
        let sender_identity_key =
            b64_decode_fixed::<32>(sender_identity_key, CryptoError::BadEnvelope)?;
        let sender_ephemeral_key =
            b64_decode_fixed::<32>(sender_ephemeral_key, CryptoError::BadEnvelope)?;
        let envelope_aad = aad::prekey(
            envelope.version,
            &sender_identity_key,
            &sender_ephemeral_key,
            *recipient_signed_prekey_id,
            *recipient_one_time_prekey_id,
        );
        let ciphertext = B64
            .decode(&envelope.ciphertext)
            .map_err(|_| CryptoError::BadEnvelope)?;

        if self.sessions.contains_key(peer_id) {
            return self.decrypt_existing(
                peer_id,
                &header,
                &ciphertext,
                &envelope_aad,
                processed_message_id,
            );
        }

        let mut session = self.create_bob_session(
            &sender_identity_key,
            &sender_ephemeral_key,
            *recipient_signed_prekey_id,
            *recipient_one_time_prekey_id,
        )?;
        let plaintext = ratchet::decrypt(&mut session, &header, &ciphertext, &envelope_aad)
            .map_err(|_| CryptoError::DecryptFailed)?;

        self.sessions.insert(
            peer_id.to_owned(),
            PeerSession {
                ratchet: session,
                prekey_header: None,
                prekey_expires_at: None,
            },
        );
        let consumed_opk = recipient_one_time_prekey_id
            .and_then(|opk_id| self.take_one_time_prekey(opk_id).map(|opk| (opk_id, opk)));
        let inserted_marker = processed_message_id
            .is_some_and(|message_id| self.mark_processed(peer_id, message_id, &plaintext));

        if let Err(error) = self.persist_decrypt(peer_id, processed_message_id) {
            self.sessions.remove(peer_id);
            if let Some((opk_id, (opk, created_at))) = consumed_opk {
                self.restore_one_time_prekey(opk_id, opk, created_at);
            }
            if inserted_marker {
                self.remove_processed(peer_id, processed_message_id.unwrap_or_default());
            }
            return Err(CryptoError::Persistence(error));
        }
        Ok(plaintext)
    }

    /// Bob's X3DH: use stored SPK (and optionally OPK) to derive the shared secret.
    /// OPK is not consumed here, only after AEAD authentication succeeds.
    #[allow(clippy::similar_names)]
    fn create_bob_session(
        &self,
        sender_identity_key: &[u8; 32],
        sender_ephemeral_key: &[u8; 32],
        expected_spk_id: u32,
        opk_id: Option<u32>,
    ) -> Result<SessionState, CryptoError> {
        let spk = self
            .stored_spk
            .iter()
            .chain(&self.previous_spks)
            .find(|spk| spk.key_id() == expected_spk_id)
            .ok_or(CryptoError::BadEnvelope)?;
        let peer_vk =
            VerifyingKey::from_bytes(sender_identity_key).map_err(|_| CryptoError::BadEnvelope)?;
        let peer_ek = X25519PublicKey::from(*sender_ephemeral_key);
        let opk_ref = match opk_id {
            Some(id) => Some(self.stored_opks.get(&id).ok_or(CryptoError::BadEnvelope)?),
            None => None,
        };
        let bob_secret = x3dh::bob_respond(&self.identity, spk, opk_ref, &peer_vk, &peer_ek)
            .map_err(|_| CryptoError::X3dhFailed)?;
        let bob_ratchet =
            RatchetKeyPair::from_bytes(spk.secret().to_bytes(), spk.public().to_bytes());
        Ok(ratchet::initialize_bob(bob_secret, bob_ratchet))
    }

    fn decrypt_existing(
        &mut self,
        peer_id: &str,
        header: &RatchetHeader,
        ciphertext: &[u8],
        envelope_aad: &[u8],
        processed_message_id: Option<&str>,
    ) -> Result<Vec<u8>, CryptoError> {
        let original = self
            .sessions
            .get(peer_id)
            .cloned()
            .ok_or(CryptoError::NoSession)?;
        let plaintext = {
            let session = self
                .sessions
                .get_mut(peer_id)
                .ok_or(CryptoError::NoSession)?;
            ratchet::decrypt(&mut session.ratchet, header, ciphertext, envelope_aad)
                .map_err(|_| CryptoError::DecryptFailed)?
        };
        let inserted_marker = processed_message_id
            .is_some_and(|message_id| self.mark_processed(peer_id, message_id, &plaintext));

        if let Err(error) = self.persist_decrypt(peer_id, processed_message_id) {
            self.sessions.insert(peer_id.to_owned(), original);
            if inserted_marker {
                self.remove_processed(peer_id, processed_message_id.unwrap_or_default());
            }
            return Err(CryptoError::Persistence(error));
        }
        Ok(plaintext)
    }

    pub(crate) fn decrypt_message_to_text(
        &mut self,
        peer_id: &str,
        message_id: &MessageId,
        envelope: &EncryptedEnvelope,
    ) -> InboundDecrypt {
        if envelope.version != consts::PROTOCOL_VERSION {
            return InboundDecrypt::Failed;
        }
        let message_id = message_id.to_string();
        if let Some(processed) = self
            .processed_messages
            .get(peer_id)
            .and_then(|messages| messages.get(&message_id))
        {
            return processed
                .pending_plaintext
                .as_ref()
                .map_or(InboundDecrypt::Duplicate, |text| {
                    InboundDecrypt::Pending(text.clone())
                });
        }
        match self.decrypt_with_marker(peer_id, envelope, Some(&message_id)) {
            Ok(plaintext) => InboundDecrypt::Pending(
                String::from_utf8(plaintext).unwrap_or_else(|_| "[invalid utf-8]".to_owned()),
            ),
            Err(_) => InboundDecrypt::Failed,
        }
    }
}

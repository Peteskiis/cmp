//! Client-side identity, X3DH, Double Ratchet, and session persistence.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crypto::keys::{IdentityKeyPair, OneTimePreKey, RatchetKeyPair, SignedPreKey};
use crypto::ratchet::{self, RatchetHeader, RatchetMessage, SessionState};
use crypto::x3dh::{self, PeerPreKeyBundle};
use ed25519_dalek::VerifyingKey;
use protocol::types::{EncryptedEnvelope, MessageHeader, RatchetHeader as ProtoRatchetHeader};
use protocol::{ClientMessage, MessageId, UserId};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::crypto_decode::{b64_decode_fixed, decode_ratchet_header};
use crate::crypto_outbox::{PendingOutbound, ensure_capacity};
use crate::crypto_replay::{ProcessedMessage, now_secs, prune_processed, validate_peer_ids};
use crate::crypto_store;

const LEGACY_PREKEY_ID_FLOOR: u32 = 1 << 31;

#[path = "crypto_mgr_persistence.rs"]
mod persistence;
use persistence::{decode_stored_opks, decode_stored_spk, restore_entry};

#[path = "crypto_mgr_prekeys.rs"]
mod prekeys;

#[path = "crypto_mgr_outbound.rs"]
mod outbound;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum CryptoError {
    #[error("invalid pre-key bundle")]
    BadBundle,
    #[error("invalid envelope")]
    BadEnvelope,
    #[error("key agreement failed")]
    X3dhFailed,
    #[error("ratchet error")]
    RatchetFailed,
    #[error("no session with peer")]
    NoSession,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("cryptographic state could not be persisted")]
    Persistence(#[source] anyhow::Error),
    #[error("durable message queue is full")]
    OutboxFull,
    #[error("waiting for the server to accept the first message")]
    AwaitingPrekeyAdmission,
    #[error("processed-message ledger is full")]
    ReplayLedgerFull,
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct StoredSpk {
    key_id: u32,
    secret_bytes: [u8; 32],
    public_bytes: [u8; 32],
    signature_b64: String,
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct StoredOpk {
    key_id: u32,
    secret_bytes: [u8; 32],
    public_bytes: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredX3dhResult {
    ephemeral_public: [u8; 32],
    recipient_signed_prekey_id: u32,
    recipient_one_time_prekey_id: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PeerSession {
    ratchet: SessionState,
    prekey_header: Option<StoredX3dhResult>,
    #[serde(default)]
    prekey_expires_at: Option<u64>,
}

pub(crate) enum InboundDecrypt {
    Pending(String),
    Duplicate,
    Failed,
}

#[derive(Default, Deserialize)]
struct CoreState {
    signed_prekey: Option<StoredSpk>,
    #[serde(default)]
    previous_signed_prekeys: Vec<StoredSpk>,
    #[serde(default)]
    signed_prekey_rotated_at: u64,
    one_time_prekeys: Vec<StoredOpk>,
    sessions: HashMap<String, PeerSession>,
    #[serde(default)]
    next_one_time_prekey_id: Option<u32>,
    #[serde(default)]
    one_time_prekey_created_at: HashMap<u32, u64>,
}

pub(crate) struct CryptoManager {
    identity: IdentityKeyPair,
    sessions: HashMap<String, PeerSession>,
    pending_inits: HashSet<String>,
    stored_spk: Option<SignedPreKey>,
    previous_spks: Vec<SignedPreKey>,
    signed_prekey_rotated_at: u64,
    stored_opks: HashMap<u32, OneTimePreKey>,
    next_one_time_prekey_id: u32,
    one_time_prekey_created_at: HashMap<u32, u64>,
    pending_outbound: Vec<PendingOutbound>,
    processed_messages: HashMap<String, HashMap<String, ProcessedMessage>>,
    store: crypto_store::CryptoStore,
    fail_persistence: bool,
}

impl CryptoManager {
    /// Load or generate identity, SPK, OPKs, and sessions from `data_dir`.
    pub(crate) fn load_or_generate(data_dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))?;
        }
        let key_path = data_dir.join("identity.key");
        let identity = if key_path.exists() {
            let bytes = fs::read(&key_path)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("corrupt identity key file"))?;
            IdentityKeyPair::from_bytes(&arr)
        } else {
            let ik = IdentityKeyPair::generate();
            crypto_store::write_new(&key_path, &ik.to_bytes())?;
            ik
        };

        let store = crypto_store::CryptoStore::open(&data_dir.join("crypto.db"))?;
        let persisted: CoreState = store.load_core()?;
        let pending_outbound = store.load_outbox()?;
        let mut processed_messages: HashMap<String, HashMap<String, ProcessedMessage>> =
            HashMap::new();
        for row in store.load_processed()? {
            processed_messages.entry(row.peer_id).or_default().insert(
                row.message_id,
                ProcessedMessage {
                    pending_plaintext: row.pending_plaintext,
                    processed_at: row.processed_at,
                },
            );
        }
        let stored_spk = decode_stored_spk(persisted.signed_prekey)?;
        let previous_spks = persisted
            .previous_signed_prekeys
            .into_iter()
            .map(|stored| {
                decode_stored_spk(Some(stored))?
                    .ok_or_else(|| anyhow::anyhow!("corrupt previous signed prekey"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let stored_opks = decode_stored_opks(persisted.one_time_prekeys);
        let mut one_time_prekey_created_at = persisted.one_time_prekey_created_at;
        let loaded_at = now_secs();
        one_time_prekey_created_at.retain(|key_id, _| stored_opks.contains_key(key_id));
        for key_id in stored_opks.keys() {
            one_time_prekey_created_at
                .entry(*key_id)
                .or_insert(loaded_at);
        }
        let derived_next_id = stored_opks
            .keys()
            .max()
            .map_or(0, |key_id| key_id.saturating_add(1));
        let next_one_time_prekey_id = persisted
            .next_one_time_prekey_id
            .unwrap_or_default()
            .max(derived_next_id)
            .max(LEGACY_PREKEY_ID_FLOOR);
        validate_peer_ids(&persisted.sessions)?;
        validate_peer_ids(&processed_messages)?;
        let cutoff = now_secs().saturating_sub(crate::crypto_replay::RETENTION_SECS);
        store.prune_processed(cutoff)?;
        prune_processed(&mut processed_messages, now_secs());

        Ok(Self {
            identity,
            sessions: persisted.sessions,
            pending_inits: HashSet::new(),
            stored_spk,
            previous_spks,
            signed_prekey_rotated_at: persisted.signed_prekey_rotated_at,
            stored_opks,
            next_one_time_prekey_id,
            one_time_prekey_created_at,
            pending_outbound,
            processed_messages,
            store,
            fail_persistence: false,
        })
    }

    pub(crate) const fn needs_registration(&self) -> bool {
        self.stored_spk.is_none()
    }

    pub(crate) const fn identity(&self) -> &IdentityKeyPair {
        &self.identity
    }

    pub(crate) fn add_pending(&mut self, peer_id: &str) {
        self.pending_inits.insert(peer_id.to_owned());
    }

    pub(crate) fn is_pending(&self, peer_id: &str) -> bool {
        self.pending_inits.contains(peer_id)
    }

    pub(crate) fn pending_peers(&self) -> Vec<String> {
        self.pending_inits.iter().cloned().collect()
    }

    /// Initialize a session with a peer using their pre-key bundle (Alice's side).
    pub(crate) fn init_session_from_bundle(
        &mut self,
        peer_id: &str,
        bundle: &protocol::PreKeyBundle,
    ) -> Result<(), CryptoError> {
        let peer_vk = VerifyingKey::from_bytes(&b64_decode_fixed::<32>(
            &bundle.identity_key,
            CryptoError::BadBundle,
        )?)
        .map_err(|_| CryptoError::BadBundle)?;
        let spk_public = X25519PublicKey::from(b64_decode_fixed::<32>(
            &bundle.signed_prekey,
            CryptoError::BadBundle,
        )?);
        let spk_sig = ed25519_dalek::Signature::from_bytes(&b64_decode_fixed::<64>(
            &bundle.signed_prekey_signature,
            CryptoError::BadBundle,
        )?);

        let opk = match &bundle.one_time_prekey {
            Some(otk) => {
                let pk = b64_decode_fixed::<32>(&otk.public_key, CryptoError::BadBundle)?;
                Some((otk.key_id, X25519PublicKey::from(pk)))
            }
            None => None,
        };

        let peer_bundle = PeerPreKeyBundle {
            identity_key: peer_vk,
            signed_prekey: spk_public,
            signed_prekey_id: bundle.signed_prekey_id,
            signed_prekey_signature: spk_sig,
            one_time_prekey: opk,
        };

        let x3dh_result = x3dh::alice_initiate(&self.identity, &peer_bundle)
            .map_err(|_| CryptoError::X3dhFailed)?;

        let x3dh_data = StoredX3dhResult {
            ephemeral_public: x3dh_result.ephemeral_public.to_bytes(),
            recipient_signed_prekey_id: bundle.signed_prekey_id,
            recipient_one_time_prekey_id: opk.map(|(id, _)| id),
        };
        let session = ratchet::initialize_alice(x3dh_result.shared_secret, &spk_public)
            .map_err(|_| CryptoError::RatchetFailed)?;

        let previous = self.sessions.insert(
            peer_id.to_owned(),
            PeerSession {
                ratchet: session,
                prekey_header: Some(x3dh_data),
                prekey_expires_at: Some(
                    now_secs().saturating_add(protocol::consts::ONE_TIME_PREKEY_RESERVATION_SECS),
                ),
            },
        );
        if let Err(error) = self.persist_state() {
            restore_entry(&mut self.sessions, peer_id, previous);
            return Err(CryptoError::Persistence(error));
        }
        self.pending_inits.remove(peer_id);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn encrypt(
        &mut self,
        peer_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, CryptoError> {
        let (original, envelope) = self.advance_encryption(peer_id, plaintext)?;
        if let Err(error) = self.persist_state() {
            self.sessions.insert(peer_id.to_owned(), original);
            return Err(CryptoError::Persistence(error));
        }
        Ok(envelope)
    }

    pub(crate) fn encrypt_message(
        &mut self,
        peer_id: &str,
        recipient_id: &UserId,
        message_id: &MessageId,
        plaintext: &[u8],
    ) -> Result<ClientMessage, CryptoError> {
        if self.pending_outbound.iter().any(|pending| {
            matches!(
                pending,
                PendingOutbound::Message {
                    recipient_id: pending_recipient,
                    envelope: EncryptedEnvelope { header: MessageHeader::PreKey { .. }, .. },
                    ..
                } if pending_recipient == recipient_id
            )
        }) {
            return Err(CryptoError::AwaitingPrekeyAdmission);
        }
        ensure_capacity(&self.pending_outbound, plaintext.len())?;
        let (original_session, envelope) = self.advance_encryption(peer_id, plaintext)?;
        let pending = PendingOutbound::Message {
            recipient_id: recipient_id.clone(),
            message_id: message_id.clone(),
            envelope,
        };
        self.pending_outbound.push(pending.clone());

        if let Err(error) = self.persist_outbound(&pending) {
            self.sessions.insert(peer_id.to_owned(), original_session);
            self.pending_outbound.pop();
            return Err(CryptoError::Persistence(error));
        }
        Ok(pending.to_client_message())
    }

    pub(crate) fn confirm_read_receipt_sent(
        &mut self,
        receipt_id: &MessageId,
    ) -> anyhow::Result<()> {
        let Some(index) = self.pending_outbound.iter().position(|pending| {
            matches!(
                pending,
                PendingOutbound::ReadReceipt { receipt_id: pending_id, .. }
                    if pending_id == receipt_id
            )
        }) else {
            return Ok(());
        };
        let pending = self.pending_outbound.remove(index);
        if let Err(error) = self.store.delete_outbound(&receipt_id.to_string()) {
            self.pending_outbound.insert(index, pending);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn confirm_acked(
        &mut self,
        ack_id: &MessageId,
        message_ids: &[MessageId],
    ) -> anyhow::Result<()> {
        let Some(pending_index) = self.pending_outbound.iter().position(|pending| {
            matches!(
                pending,
                PendingOutbound::Ack { ack_id: pending_id, .. }
                    | PendingOutbound::ReadReceiptAck { ack_id: pending_id, .. }
                    if pending_id == ack_id
            )
        }) else {
            return Ok(());
        };
        let expected_ids = match &self.pending_outbound[pending_index] {
            PendingOutbound::Ack { message_ids, .. } => message_ids.clone(),
            PendingOutbound::ReadReceiptAck { receipt_ids, .. } => receipt_ids.clone(),
            _ => return Ok(()),
        };
        if expected_ids != message_ids {
            return Ok(());
        }

        let previous = self.processed_messages.clone();
        let pending = self.pending_outbound.remove(pending_index);
        for message_id in &expected_ids {
            let key = message_id.to_string();
            for messages in self.processed_messages.values_mut() {
                messages.remove(&key);
            }
        }
        self.processed_messages
            .retain(|_, messages| !messages.is_empty());
        let ids: Vec<String> = message_ids.iter().map(ToString::to_string).collect();
        if let Err(error) = self.store.confirm_ack(&ack_id.to_string(), &ids) {
            self.processed_messages = previous;
            self.pending_outbound.insert(pending_index, pending);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn queue_ack(
        &mut self,
        message_ids: Vec<MessageId>,
    ) -> Result<ClientMessage, CryptoError> {
        ensure_capacity(&self.pending_outbound, message_ids.len() * 36)?;
        let pending = PendingOutbound::Ack {
            ack_id: MessageId::new(),
            message_ids,
        };
        self.pending_outbound.push(pending.clone());
        if let Err(error) = self.persist_outbound(&pending) {
            self.pending_outbound.pop();
            return Err(CryptoError::Persistence(error));
        }
        Ok(pending.to_client_message())
    }

    pub(crate) fn queue_read_receipt_ack(
        &mut self,
        receipt_ids: Vec<MessageId>,
    ) -> Result<ClientMessage, CryptoError> {
        ensure_capacity(&self.pending_outbound, receipt_ids.len() * 36)?;
        let pending = PendingOutbound::ReadReceiptAck {
            ack_id: MessageId::new(),
            receipt_ids,
        };
        self.pending_outbound.push(pending.clone());
        if let Err(error) = self.persist_outbound(&pending) {
            self.pending_outbound.pop();
            return Err(CryptoError::Persistence(error));
        }
        Ok(pending.to_client_message())
    }

    fn advance_encryption(
        &mut self,
        peer_id: &str,
        plaintext: &[u8],
    ) -> Result<(PeerSession, EncryptedEnvelope), CryptoError> {
        let original = self
            .sessions
            .get(peer_id)
            .cloned()
            .ok_or(CryptoError::NoSession)?;
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or(CryptoError::NoSession)?;
        let RatchetMessage { header, ciphertext } =
            ratchet::encrypt(&mut session.ratchet, plaintext)
                .map_err(|_| CryptoError::RatchetFailed)?;
        let proto_ratchet = ProtoRatchetHeader {
            ratchet_key: B64.encode(header.ratchet_key),
            previous_chain_length: header.previous_chain_length,
            message_number: header.message_number,
        };
        let header = if let Some(x3dh_data) = session.prekey_header.take() {
            session.prekey_expires_at = None;
            MessageHeader::PreKey {
                sender_identity_key: B64.encode(self.identity.verifying_key().as_bytes()),
                sender_ephemeral_key: B64.encode(x3dh_data.ephemeral_public),
                recipient_signed_prekey_id: x3dh_data.recipient_signed_prekey_id,
                recipient_one_time_prekey_id: x3dh_data.recipient_one_time_prekey_id,
                ratchet: proto_ratchet,
            }
        } else {
            MessageHeader::Ratchet(proto_ratchet)
        };
        Ok((
            original,
            EncryptedEnvelope {
                version: 1,
                header,
                ciphertext: B64.encode(ciphertext),
            },
        ))
    }

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
                >= protocol::consts::MAX_PROCESSED_MESSAGES
        {
            return Err(CryptoError::ReplayLedgerFull);
        }
        if let MessageHeader::PreKey {
            sender_identity_key,
            sender_ephemeral_key,
            recipient_signed_prekey_id,
            recipient_one_time_prekey_id,
            ratchet,
            ..
        } = &envelope.header
        {
            // Parse header + ciphertext BEFORE session creation so parsing
            // failures can't leave an orphan session in the map.
            let header = decode_ratchet_header(ratchet)?;
            let ct = B64
                .decode(&envelope.ciphertext)
                .map_err(|_| CryptoError::BadEnvelope)?;

            if self.sessions.contains_key(peer_id) {
                return self.decrypt_existing(peer_id, &header, &ct, processed_message_id);
            }

            let mut session = self.create_bob_session(
                sender_identity_key,
                sender_ephemeral_key,
                *recipient_signed_prekey_id,
                *recipient_one_time_prekey_id,
            )?;
            let plaintext = ratchet::decrypt(&mut session, &header, &ct)
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
            return Ok(plaintext);
        }

        // Normal ratchet message
        let MessageHeader::Ratchet(ratchet_header) = &envelope.header else {
            return Err(CryptoError::BadEnvelope);
        };

        let header = decode_ratchet_header(ratchet_header)?;

        let ciphertext = B64
            .decode(&envelope.ciphertext)
            .map_err(|_| CryptoError::BadEnvelope)?;
        self.decrypt_existing(peer_id, &header, &ciphertext, processed_message_id)
    }

    /// Bob's X3DH: use stored SPK (and optionally OPK) to derive the shared secret.
    /// OPK is NOT consumed here — only after AEAD authentication succeeds.
    #[allow(clippy::similar_names)]
    fn create_bob_session(
        &self,
        sender_identity_key_b64: &str,
        sender_ephemeral_key_b64: &str,
        expected_spk_id: u32,
        opk_id: Option<u32>,
    ) -> Result<SessionState, CryptoError> {
        let spk = self
            .stored_spk
            .iter()
            .chain(&self.previous_spks)
            .find(|spk| spk.key_id() == expected_spk_id)
            .ok_or(CryptoError::BadEnvelope)?;

        let ik_bytes = b64_decode_fixed::<32>(sender_identity_key_b64, CryptoError::BadEnvelope)?;
        let peer_vk = VerifyingKey::from_bytes(&ik_bytes).map_err(|_| CryptoError::BadEnvelope)?;
        let ek_bytes = b64_decode_fixed::<32>(sender_ephemeral_key_b64, CryptoError::BadEnvelope)?;
        let peer_ek = X25519PublicKey::from(ek_bytes);

        // If the sender claims to have used an OPK, we must have it — silent
        // degradation to 3-DH would let a MITM strip OPK protection.
        let opk_ref = match opk_id {
            Some(id) => Some(self.stored_opks.get(&id).ok_or(CryptoError::BadEnvelope)?),
            None => None,
        };

        let bob_secret = x3dh::bob_respond(&self.identity, spk, opk_ref, &peer_vk, &peer_ek)
            .map_err(|_| CryptoError::X3dhFailed)?;

        // Bob's initial ratchet key pair must be his SPK
        let bob_ratchet =
            RatchetKeyPair::from_bytes(spk.secret().to_bytes(), spk.public().to_bytes());
        Ok(ratchet::initialize_bob(bob_secret, bob_ratchet))
    }

    fn decrypt_existing(
        &mut self,
        peer_id: &str,
        header: &RatchetHeader,
        ciphertext: &[u8],
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
            ratchet::decrypt(&mut session.ratchet, header, ciphertext)
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

    pub(crate) fn confirm_inbound_stored(
        &mut self,
        peer_id: &str,
        message_id: &MessageId,
    ) -> anyhow::Result<()> {
        let message_id = message_id.to_string();
        let Some(processed) = self
            .processed_messages
            .get_mut(peer_id)
            .and_then(|messages| messages.get_mut(&message_id))
        else {
            return Ok(());
        };
        let pending = processed.pending_plaintext.take();
        if let Err(error) = self.store.mark_processed_committed(peer_id, &message_id) {
            if let Some(processed) = self
                .processed_messages
                .get_mut(peer_id)
                .and_then(|messages| messages.get_mut(&message_id))
            {
                processed.pending_plaintext = pending;
            }
            return Err(error);
        }
        Ok(())
    }

    fn mark_processed(&mut self, peer_id: &str, message_id: &str, plaintext: &[u8]) -> bool {
        prune_processed(&mut self.processed_messages, now_secs());
        self.processed_messages
            .entry(peer_id.to_owned())
            .or_default()
            .insert(
                message_id.to_owned(),
                ProcessedMessage {
                    pending_plaintext: Some(
                        String::from_utf8(plaintext.to_vec())
                            .unwrap_or_else(|_| "[invalid utf-8]".to_owned()),
                    ),
                    processed_at: now_secs(),
                },
            )
            .is_none()
    }

    fn remove_processed(&mut self, peer_id: &str, message_id: &str) {
        let remove_peer = self
            .processed_messages
            .get_mut(peer_id)
            .is_some_and(|messages| {
                messages.remove(message_id);
                messages.is_empty()
            });
        if remove_peer {
            self.processed_messages.remove(peer_id);
        }
    }

    pub(crate) fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.contains_key(peer_id)
    }

    pub(crate) fn session_peers(&self) -> Vec<&str> {
        let mut peers: Vec<&str> = self.sessions.keys().map(String::as_str).collect();
        peers.sort_unstable();
        peers
    }

    pub(crate) fn local_identity_key_b64(&self) -> String {
        B64.encode(self.identity.verifying_key().as_bytes())
    }

    pub(crate) fn encrypt_read_receipt(
        &mut self,
        peer_id: &str,
        recipient_id: &UserId,
        message_ids: &[protocol::MessageId],
    ) -> Result<ClientMessage, CryptoError> {
        let capped = if message_ids.len() > protocol::consts::MAX_RECEIPT_BATCH {
            &message_ids[..protocol::consts::MAX_RECEIPT_BATCH]
        } else {
            message_ids
        };
        let id_strings: Vec<String> = capped.iter().map(ToString::to_string).collect();
        let plaintext = serde_json::to_vec(&id_strings).map_err(|_| CryptoError::RatchetFailed)?;
        let estimated_ct_len = (plaintext.len() + 18) / 3 * 4;
        if estimated_ct_len > protocol::consts::MAX_CIPHERTEXT_BYTES {
            return Err(CryptoError::RatchetFailed);
        }
        ensure_capacity(&self.pending_outbound, plaintext.len())?;
        let receipt_id = MessageId::new();
        let (original_session, envelope) = self.advance_encryption(peer_id, &plaintext)?;
        let pending = PendingOutbound::ReadReceipt {
            recipient_id: recipient_id.clone(),
            receipt_id,
            envelope,
        };
        self.pending_outbound.push(pending.clone());
        if let Err(error) = self.persist_outbound(&pending) {
            self.sessions.insert(peer_id.to_owned(), original_session);
            self.pending_outbound.pop();
            return Err(CryptoError::Persistence(error));
        }
        Ok(pending.to_client_message())
    }
}
#[cfg(test)]
#[path = "crypto_mgr_tests.rs"]
mod tests;

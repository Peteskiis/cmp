//! Client-side crypto manager: identity persistence, X3DH session init,
//! Double Ratchet encrypt/decrypt, SPK/OPK/session persistence.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crypto::keys::{IdentityKeyPair, OneTimePreKey, RatchetKeyPair, SignedPreKey};
use crypto::ratchet::{self, RatchetHeader, RatchetMessage, SessionState};
use crypto::x3dh::{self, PeerPreKeyBundle};
use ed25519_dalek::VerifyingKey;
use protocol::types::{EncryptedEnvelope, MessageHeader, RatchetHeader as ProtoRatchetHeader};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::crypto_store;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
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

/// X3DH data needed for the `PreKey` header on the first message.
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
}

#[derive(Default, Deserialize)]
struct PersistedState {
    signed_prekey: Option<StoredSpk>,
    one_time_prekeys: Vec<StoredOpk>,
    sessions: HashMap<String, PeerSession>,
}

#[derive(Serialize)]
struct PersistedStateRef<'a> {
    signed_prekey: Option<StoredSpk>,
    one_time_prekeys: Vec<StoredOpk>,
    sessions: &'a HashMap<String, PeerSession>,
}

pub struct CryptoManager {
    identity: IdentityKeyPair,
    sessions: HashMap<String, PeerSession>,
    pending_inits: HashSet<String>,
    stored_spk: Option<SignedPreKey>,
    stored_opks: HashMap<u32, OneTimePreKey>,
    data_dir: PathBuf,
    #[cfg(test)]
    fail_persistence: bool,
}

impl CryptoManager {
    /// Load or generate identity, SPK, OPKs, and sessions from `data_dir`.
    pub fn load_or_generate(data_dir: &Path) -> anyhow::Result<Self> {
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

        let persisted: PersistedState = crypto_store::load_json(&data_dir.join("state.json"))?;
        let stored_spk = decode_stored_spk(persisted.signed_prekey)?;
        let stored_opks = decode_stored_opks(persisted.one_time_prekeys);
        validate_session_peers(&persisted.sessions)?;

        Ok(Self {
            identity,
            sessions: persisted.sessions,
            pending_inits: HashSet::new(),
            stored_spk,
            stored_opks,
            data_dir: data_dir.to_owned(),
            #[cfg(test)]
            fail_persistence: false,
        })
    }

    /// Whether registration is needed (no SPK persisted locally).
    pub const fn needs_registration(&self) -> bool {
        self.stored_spk.is_none()
    }

    pub const fn identity(&self) -> &IdentityKeyPair {
        &self.identity
    }

    pub fn add_pending(&mut self, peer_id: &str) {
        self.pending_inits.insert(peer_id.to_owned());
    }

    pub fn is_pending(&self, peer_id: &str) -> bool {
        self.pending_inits.contains(peer_id)
    }

    /// Store SPK and OPK private keys after registration.
    pub fn persist_registration_keys(
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
        if let Err(error) = self.persist_state() {
            self.stored_spk = previous_spk;
            self.stored_opks = previous_opks;
            return Err(error);
        }
        Ok(())
    }

    /// Initialize a session with a peer using their pre-key bundle (Alice's side).
    pub fn init_session_from_bundle(
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
            },
        );
        if let Err(error) = self.persist_state() {
            restore_entry(&mut self.sessions, peer_id, previous);
            return Err(CryptoError::Persistence(error));
        }
        self.pending_inits.remove(peer_id);
        Ok(())
    }

    pub fn encrypt(
        &mut self,
        peer_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, CryptoError> {
        let original = self
            .sessions
            .get(peer_id)
            .cloned()
            .ok_or(CryptoError::NoSession)?;

        let (header, ciphertext, prekey_header) = {
            let session = self
                .sessions
                .get_mut(peer_id)
                .ok_or(CryptoError::NoSession)?;
            let RatchetMessage { header, ciphertext } =
                ratchet::encrypt(&mut session.ratchet, plaintext)
                    .map_err(|_| CryptoError::RatchetFailed)?;
            (header, ciphertext, session.prekey_header.take())
        };

        let proto_header = if let Some(x3dh_data) = prekey_header {
            MessageHeader::PreKey {
                sender_identity_key: B64.encode(self.identity.verifying_key().as_bytes()),
                sender_ephemeral_key: B64.encode(x3dh_data.ephemeral_public),
                recipient_signed_prekey_id: x3dh_data.recipient_signed_prekey_id,
                recipient_one_time_prekey_id: x3dh_data.recipient_one_time_prekey_id,
                ratchet: ProtoRatchetHeader {
                    ratchet_key: B64.encode(header.ratchet_key),
                    previous_chain_length: header.previous_chain_length,
                    message_number: header.message_number,
                },
            }
        } else {
            MessageHeader::Ratchet(ProtoRatchetHeader {
                ratchet_key: B64.encode(header.ratchet_key),
                previous_chain_length: header.previous_chain_length,
                message_number: header.message_number,
            })
        };

        if let Err(error) = self.persist_state() {
            self.sessions.insert(peer_id.to_owned(), original);
            return Err(CryptoError::Persistence(error));
        }

        Ok(EncryptedEnvelope {
            version: 1,
            header: proto_header,
            ciphertext: B64.encode(ciphertext),
        })
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn decrypt(
        &mut self,
        peer_id: &str,
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>, CryptoError> {
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
                return self.decrypt_existing(peer_id, &header, &ct);
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
                },
            );
            let consumed_opk = recipient_one_time_prekey_id
                .and_then(|opk_id| self.stored_opks.remove(&opk_id).map(|opk| (opk_id, opk)));

            if let Err(error) = self.persist_state() {
                self.sessions.remove(peer_id);
                if let Some((opk_id, opk)) = consumed_opk {
                    self.stored_opks.insert(opk_id, opk);
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
        self.decrypt_existing(peer_id, &header, &ciphertext)
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
        let spk = self.stored_spk.as_ref().ok_or(CryptoError::NoSession)?;
        // Validate the sender used the SPK we actually have
        if spk.key_id() != expected_spk_id {
            return Err(CryptoError::BadEnvelope);
        }

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

        if let Err(error) = self.persist_state() {
            self.sessions.insert(peer_id.to_owned(), original);
            return Err(CryptoError::Persistence(error));
        }
        Ok(plaintext)
    }

    /// Returns `(text, decrypted_ok)` — callers should only ack if `decrypted_ok`.
    pub fn decrypt_to_text(
        &mut self,
        peer_id: &str,
        envelope: &EncryptedEnvelope,
    ) -> (String, bool) {
        match self.decrypt(peer_id, envelope) {
            Ok(plaintext) => {
                let text =
                    String::from_utf8(plaintext).unwrap_or_else(|_| "[invalid utf-8]".to_owned());
                (text, true)
            }
            Err(_) => ("[undecryptable message]".to_owned(), false),
        }
    }

    pub fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.contains_key(peer_id)
    }

    pub fn session_peers(&self) -> Vec<&str> {
        let mut peers: Vec<&str> = self.sessions.keys().map(String::as_str).collect();
        peers.sort_unstable();
        peers
    }

    /// Base64-encoded local identity public key (Ed25519 verifying key).
    pub fn local_identity_key_b64(&self) -> String {
        B64.encode(self.identity.verifying_key().as_bytes())
    }

    /// Encrypt a read receipt (list of message ID strings) using the E2EE session.
    pub fn encrypt_read_receipt(
        &mut self,
        peer_id: &str,
        message_ids: &[protocol::MessageId],
    ) -> Result<EncryptedEnvelope, CryptoError> {
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
        self.encrypt(peer_id, &plaintext)
    }

    /// Extract the sender's identity key from a `PreKey` envelope header.
    /// Returns `None` for `Ratchet` headers (non-initial messages).
    pub const fn extract_sender_identity_key(envelope: &EncryptedEnvelope) -> Option<&str> {
        match &envelope.header {
            MessageHeader::PreKey {
                sender_identity_key,
                ..
            } => Some(sender_identity_key.as_str()),
            _ => None,
        }
    }

    fn persist_state(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.fail_persistence {
            return Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "injected disk-full failure",
            )
            .into());
        }

        let signed_prekey = self.stored_spk.as_ref().map(|spk| StoredSpk {
            key_id: spk.key_id(),
            secret_bytes: spk.secret().to_bytes(),
            public_bytes: spk.public().to_bytes(),
            signature_b64: B64.encode(spk.signature().to_bytes()),
        });
        let one_time_prekeys = self
            .stored_opks
            .values()
            .map(|opk| StoredOpk {
                key_id: opk.key_id(),
                secret_bytes: opk.secret().to_bytes(),
                public_bytes: opk.public().to_bytes(),
            })
            .collect();
        let state = PersistedStateRef {
            signed_prekey,
            one_time_prekeys,
            sessions: &self.sessions,
        };
        crypto_store::write_json_atomic(&self.data_dir.join("state.json"), &state)
    }
}

// ── File persistence helpers ──

fn decode_stored_spk(stored: Option<StoredSpk>) -> anyhow::Result<Option<SignedPreKey>> {
    let Some(stored) = stored else {
        return Ok(None);
    };
    let sig_bytes = B64.decode(&stored.signature_b64)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("corrupt signed prekey signature"))?;
    Ok(Some(SignedPreKey::from_parts(
        stored.key_id,
        stored.secret_bytes,
        stored.public_bytes,
        ed25519_dalek::Signature::from_bytes(&sig_arr),
    )))
}

fn decode_stored_opks(stored: Vec<StoredOpk>) -> HashMap<u32, OneTimePreKey> {
    stored
        .into_iter()
        .map(|s| {
            (
                s.key_id,
                OneTimePreKey::from_parts(s.key_id, s.secret_bytes, s.public_bytes),
            )
        })
        .collect()
}

fn validate_session_peers(sessions: &HashMap<String, PeerSession>) -> anyhow::Result<()> {
    for peer_id in sessions.keys() {
        if protocol::UserId::new(peer_id).is_err() {
            anyhow::bail!("invalid peer ID in persisted cryptographic state");
        }
    }
    Ok(())
}

fn restore_entry(
    sessions: &mut HashMap<String, PeerSession>,
    peer_id: &str,
    previous: Option<PeerSession>,
) {
    if let Some(session) = previous {
        sessions.insert(peer_id.to_owned(), session);
    } else {
        sessions.remove(peer_id);
    }
}

fn b64_decode_fixed<const N: usize>(s: &str, err: CryptoError) -> Result<[u8; N], CryptoError> {
    let bytes = B64.decode(s).map_err(|_| err)?;
    bytes.try_into().map_err(|_| CryptoError::BadBundle)
}

fn decode_ratchet_header(proto: &ProtoRatchetHeader) -> Result<RatchetHeader, CryptoError> {
    Ok(RatchetHeader {
        ratchet_key: b64_decode_fixed::<32>(&proto.ratchet_key, CryptoError::BadEnvelope)?,
        previous_chain_length: proto.previous_chain_length,
        message_number: proto.message_number,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Set up Alice and Bob CryptoManagers with registration keys.
    fn setup_alice_and_bob() -> (CryptoManager, CryptoManager, TempDir, TempDir) {
        let alice_dir = TempDir::new().unwrap();
        let bob_dir = TempDir::new().unwrap();

        let mut alice = CryptoManager::load_or_generate(alice_dir.path()).unwrap();
        let mut bob = CryptoManager::load_or_generate(bob_dir.path()).unwrap();

        // Bob registers — persist SPK + OPKs
        let bob_spk = SignedPreKey::generate(0, bob.identity());
        let bob_opks = crypto::keys::generate_one_time_prekeys(0, 5).unwrap();
        bob.persist_registration_keys(&bob_spk, &bob_opks).unwrap();

        // Alice gets Bob's bundle (simulating server fetch)
        let bundle = protocol::PreKeyBundle {
            identity_key: B64.encode(bob.identity().verifying_key().as_bytes()),
            signed_prekey: B64.encode(bob_spk.public().as_bytes()),
            signed_prekey_id: bob_spk.key_id(),
            signed_prekey_signature: B64.encode(bob_spk.signature().to_bytes()),
            one_time_prekey: Some(protocol::OneTimePreKey {
                key_id: bob_opks[0].key_id(),
                public_key: B64.encode(bob_opks[0].public().as_bytes()),
            }),
        };
        alice.init_session_from_bundle("bob", &bundle).unwrap();

        (alice, bob, alice_dir, bob_dir)
    }

    #[test]
    fn alice_encrypt_bob_decrypt_prekey() {
        let (mut alice, mut bob, _a_dir, _b_dir) = setup_alice_and_bob();

        let envelope = alice.encrypt("bob", b"hello bob").unwrap();
        // Should be a PreKey message
        assert!(matches!(envelope.header, MessageHeader::PreKey { .. }));

        let plaintext = bob.decrypt("alice", &envelope).unwrap();
        assert_eq!(plaintext, b"hello bob");

        // Bob should now have a session
        assert!(bob.has_session("alice"));
        // OPK should be consumed
        assert!(bob.stored_opks.is_empty() || bob.stored_opks.len() == 4);
    }

    #[test]
    fn forged_prekey_no_orphan_session_no_opk_consumed() {
        let (_alice, mut bob, _a_dir, _b_dir) = setup_alice_and_bob();
        let opk_count_before = bob.stored_opks.len();

        // Forge a PreKey message with garbage ciphertext
        let forged = EncryptedEnvelope {
            version: 1,
            header: MessageHeader::PreKey {
                sender_identity_key: B64.encode([1u8; 32]),
                sender_ephemeral_key: B64.encode([2u8; 32]),
                recipient_signed_prekey_id: 0,
                recipient_one_time_prekey_id: Some(0),
                ratchet: ProtoRatchetHeader {
                    ratchet_key: B64.encode([3u8; 32]),
                    previous_chain_length: 0,
                    message_number: 0,
                },
            },
            ciphertext: B64.encode(b"garbage"),
        };

        let result = bob.decrypt("mallory", &forged);
        assert!(result.is_err());
        // No orphan session
        assert!(!bob.has_session("mallory"));
        // OPK not consumed
        assert_eq!(bob.stored_opks.len(), opk_count_before);
    }

    #[test]
    fn existing_session_not_destroyed_by_prekey() {
        let (mut alice, mut bob, _a_dir, _b_dir) = setup_alice_and_bob();

        // Alice sends first message — Bob creates session
        let env1 = alice.encrypt("bob", b"first").unwrap();
        bob.decrypt("alice", &env1).unwrap();
        assert!(bob.has_session("alice"));

        // Forge a PreKey from "alice" with garbage — should NOT destroy session
        let forged = EncryptedEnvelope {
            version: 1,
            header: MessageHeader::PreKey {
                sender_identity_key: B64.encode([9u8; 32]),
                sender_ephemeral_key: B64.encode([9u8; 32]),
                recipient_signed_prekey_id: 0,
                recipient_one_time_prekey_id: None,
                ratchet: ProtoRatchetHeader {
                    ratchet_key: B64.encode([9u8; 32]),
                    previous_chain_length: 0,
                    message_number: 0,
                },
            },
            ciphertext: B64.encode(b"fake"),
        };
        let _ = bob.decrypt("alice", &forged); // should fail but NOT nuke session

        // Session still works
        assert!(bob.has_session("alice"));
        let env2 = alice.encrypt("bob", b"second").unwrap();
        let pt2 = bob.decrypt("alice", &env2).unwrap();
        assert_eq!(pt2, b"second");
    }

    #[test]
    fn missing_opk_returns_error() {
        let (_alice, mut bob, _a_dir, _b_dir) = setup_alice_and_bob();

        // PreKey message claiming OPK 999 which Bob doesn't have
        let forged = EncryptedEnvelope {
            version: 1,
            header: MessageHeader::PreKey {
                sender_identity_key: B64.encode([1u8; 32]),
                sender_ephemeral_key: B64.encode([2u8; 32]),
                recipient_signed_prekey_id: 0,
                recipient_one_time_prekey_id: Some(999),
                ratchet: ProtoRatchetHeader {
                    ratchet_key: B64.encode([3u8; 32]),
                    previous_chain_length: 0,
                    message_number: 0,
                },
            },
            ciphertext: B64.encode(b"anything"),
        };

        let result = bob.decrypt("someone", &forged);
        assert!(result.is_err());
    }

    #[test]
    fn persistence_roundtrip() {
        let (mut alice, mut bob, _a_dir, b_dir) = setup_alice_and_bob();

        // Alice sends, Bob decrypts
        let env1 = alice.encrypt("bob", b"persist me").unwrap();
        bob.decrypt("alice", &env1).unwrap();

        // Reload Bob from disk
        let mut bob2 = CryptoManager::load_or_generate(b_dir.path()).unwrap();
        assert!(bob2.has_session("alice"));

        // Alice sends another message — Bob2 should decrypt it
        let env2 = alice.encrypt("bob", b"after reload").unwrap();
        let pt2 = bob2.decrypt("alice", &env2).unwrap();
        assert_eq!(pt2, b"after reload");
    }

    #[test]
    fn disk_full_during_encrypt_does_not_release_or_advance_ciphertext() {
        let (mut alice, mut bob, a_dir, _b_dir) = setup_alice_and_bob();
        alice.fail_persistence = true;

        let result = alice.encrypt("bob", b"send after restart");
        assert!(matches!(result, Err(CryptoError::Persistence(_))));
        drop(alice);

        let mut restarted = CryptoManager::load_or_generate(a_dir.path()).unwrap();
        let envelope = restarted.encrypt("bob", b"send after restart").unwrap();
        assert!(matches!(envelope.header, MessageHeader::PreKey { .. }));
        assert_eq!(
            bob.decrypt("alice", &envelope).unwrap(),
            b"send after restart"
        );
    }

    #[test]
    fn disk_full_during_decrypt_preserves_session_and_opk_for_restart() {
        let (mut alice, mut bob, _a_dir, b_dir) = setup_alice_and_bob();
        let envelope = alice.encrypt("bob", b"retry after restart").unwrap();
        let opk_count = bob.stored_opks.len();
        bob.fail_persistence = true;

        let result = bob.decrypt("alice", &envelope);
        assert!(matches!(result, Err(CryptoError::Persistence(_))));
        assert!(!bob.has_session("alice"));
        assert_eq!(bob.stored_opks.len(), opk_count);
        drop(bob);

        let mut restarted = CryptoManager::load_or_generate(b_dir.path()).unwrap();
        assert_eq!(
            restarted.decrypt("alice", &envelope).unwrap(),
            b"retry after restart"
        );
    }

    #[test]
    fn corrupt_persisted_state_is_not_silently_discarded() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("state.json"), b"not json").unwrap();

        assert!(CryptoManager::load_or_generate(directory.path()).is_err());
    }
}

//! Client-side crypto manager: identity persistence, X3DH session init,
//! Double Ratchet encrypt/decrypt.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crypto::keys::IdentityKeyPair;
use crypto::ratchet::{self, RatchetHeader, RatchetMessage, SessionState};
use crypto::x3dh::{self, PeerPreKeyBundle};
use ed25519_dalek::VerifyingKey;
use protocol::types::{EncryptedEnvelope, MessageHeader, RatchetHeader as ProtoRatchetHeader};
use x25519_dalek::PublicKey as X25519PublicKey;

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
}

pub struct CryptoManager {
    identity: IdentityKeyPair,
    sessions: HashMap<String, SessionState>,
    /// Peers awaiting `PreKeyBundleResponse` to complete session init.
    pending_inits: HashSet<String>,
    /// Stored X3DH results for creating `PreKey` headers on first messages.
    prekey_headers: HashMap<String, StoredX3dhResult>,
    #[allow(dead_code)]
    data_dir: PathBuf,
}

struct StoredX3dhResult {
    ephemeral_public: [u8; 32],
    recipient_signed_prekey_id: u32,
    recipient_one_time_prekey_id: Option<u32>,
}

impl CryptoManager {
    pub fn load_or_generate(data_dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(data_dir)?;
        let key_path = data_dir.join("identity.key");

        let identity = if key_path.exists() {
            let bytes = fs::read(&key_path)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("corrupt identity key file"))?;
            IdentityKeyPair::from_bytes(&arr)
        } else {
            let ik = IdentityKeyPair::generate();
            write_key_file(&key_path, &ik.to_bytes())?;
            ik
        };

        Ok(Self {
            identity,
            sessions: HashMap::new(),
            pending_inits: HashSet::new(),
            prekey_headers: HashMap::new(),
            data_dir: data_dir.to_owned(),
        })
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

    /// Initialize a session with a peer using their pre-key bundle.
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

        self.prekey_headers.insert(
            peer_id.to_owned(),
            StoredX3dhResult {
                ephemeral_public: x3dh_result.ephemeral_public.to_bytes(),
                recipient_signed_prekey_id: bundle.signed_prekey_id,
                recipient_one_time_prekey_id: opk.map(|(id, _)| id),
            },
        );

        let session = ratchet::initialize_alice(x3dh_result.shared_secret, &spk_public)
            .map_err(|_| CryptoError::RatchetFailed)?;

        self.sessions.insert(peer_id.to_owned(), session);
        self.pending_inits.remove(peer_id);
        Ok(())
    }

    pub fn encrypt(
        &mut self,
        peer_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, CryptoError> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or(CryptoError::NoSession)?;

        let RatchetMessage { header, ciphertext } =
            ratchet::encrypt(session, plaintext).map_err(|_| CryptoError::RatchetFailed)?;

        let proto_header = if let Some(x3dh_data) = self.prekey_headers.remove(peer_id) {
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

        Ok(EncryptedEnvelope {
            version: 1,
            header: proto_header,
            ciphertext: B64.encode(ciphertext),
        })
    }

    pub fn decrypt(
        &mut self,
        peer_id: &str,
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>, CryptoError> {
        // PreKey messages require Bob to have his original SPK private key.
        // Until SPK persistence is implemented, Bob must establish sessions
        // via /chat (which fetches the peer's bundle). Return NoSession so
        // the message is not acked and will be re-delivered.
        let ratchet_header = match &envelope.header {
            MessageHeader::PreKey { ratchet, .. } => ratchet,
            MessageHeader::Ratchet(h) => h,
            _ => return Err(CryptoError::BadEnvelope),
        };

        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or(CryptoError::NoSession)?;

        let header = RatchetHeader {
            ratchet_key: b64_decode_fixed::<32>(
                &ratchet_header.ratchet_key,
                CryptoError::BadEnvelope,
            )?,
            previous_chain_length: ratchet_header.previous_chain_length,
            message_number: ratchet_header.message_number,
        };

        let ciphertext = B64
            .decode(&envelope.ciphertext)
            .map_err(|_| CryptoError::BadEnvelope)?;

        ratchet::decrypt(session, &header, &ciphertext).map_err(|_| CryptoError::DecryptFailed)
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
}

fn b64_decode_fixed<const N: usize>(s: &str, err: CryptoError) -> Result<[u8; N], CryptoError> {
    let bytes = B64.decode(s).map_err(|_| err)?;
    bytes.try_into().map_err(|_| CryptoError::BadBundle)
}

fn write_key_file(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }
    Ok(())
}

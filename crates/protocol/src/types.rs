use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UserId(String);

impl UserId {
    /// Creates a new `UserId` after validating the input.
    ///
    /// # Errors
    ///
    /// Returns an error if the id is empty/whitespace-only, exceeds 128 bytes,
    /// or contains non-ASCII characters. ASCII-only prevents Unicode
    /// normalization attacks (NFC vs NFD impersonation).
    pub fn new(id: impl Into<String>) -> Result<Self, InvalidUserId> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(InvalidUserId("user id cannot be empty or whitespace-only"));
        }
        if id.len() > 128 {
            return Err(InvalidUserId("user id exceeds 128 bytes"));
        }
        if !id.is_ascii() {
            return Err(InvalidUserId("user id must be ASCII"));
        }
        if id.bytes().any(|b| b.is_ascii_control()) {
            return Err(InvalidUserId("user id contains control characters"));
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid user id: {0}")]
pub struct InvalidUserId(pub &'static str);

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<UserId> for String {
    fn from(id: UserId) -> Self {
        id.0
    }
}

impl TryFrom<String> for UserId {
    type Error = InvalidUserId;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for UserId {
    type Error = InvalidUserId;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(Uuid);

impl MessageId {
    /// Generates a new random message ID. No `Default` impl — random IDs should be explicit.
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<Uuid> for MessageId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

/// Opaque encrypted container the server routes without reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Protocol version for forward compatibility.
    pub version: u32,
    /// Unencrypted header — the receiver needs this to derive the decryption key.
    /// Also used as AAD (additional authenticated data) in AES-GCM.
    pub header: MessageHeader,
    /// Encrypted ciphertext, base64-encoded for JSON transport.
    pub ciphertext: String,
}

/// Header visible outside the ciphertext, needed by the receiver to advance
/// ratchet state and derive the correct message key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum MessageHeader {
    /// X3DH handshake material + first ratchet message.
    PreKey {
        /// Sender's Ed25519 identity key (base64).
        sender_identity_key: String,
        /// Sender's X25519 ephemeral key (base64).
        sender_ephemeral_key: String,
        /// Which of the recipient's signed pre-keys was used.
        recipient_signed_prekey_id: u32,
        /// Which one-time pre-key was consumed (`None` if unavailable).
        recipient_one_time_prekey_id: Option<u32>,
        /// Double Ratchet header for the first message.
        ratchet: RatchetHeader,
    },
    /// Normal Double Ratchet message within an established session.
    Ratchet(RatchetHeader),
}

/// Double Ratchet header — shared between `PreKey` and `Ratchet` message types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Sender's current DH ratchet public key (X25519, base64).
    pub ratchet_key: String,
    /// Number of messages sent in the previous sending chain.
    pub previous_chain_length: u32,
    /// Message index within the current sending chain.
    pub message_number: u32,
}

/// A one-time pre-key (id + X25519 public key, base64-encoded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub key_id: u32,
    pub public_key: String,
}

/// Public key material for establishing a session with a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Ed25519 public identity key (base64).
    pub identity_key: String,
    /// X25519 signed pre-key (base64).
    pub signed_prekey: String,
    pub signed_prekey_id: u32,
    /// Ed25519 signature over the signed pre-key (base64).
    pub signed_prekey_signature: String,
    /// One-time pre-key, if available.
    pub one_time_prekey: Option<OneTimePreKey>,
}

use crate::error::CryptoError;
use crate::keys::{IdentityKeyPair, OneTimePreKey, SignedPreKey};
use crate::ratchet::SessionState;

/// Persists Double Ratchet session state per peer.
pub trait SessionStore {
    /// Load a session for a peer, or `None` if no session exists.
    fn load_session(&self, peer_id: &str) -> Result<Option<SessionState>, CryptoError>;

    /// Store (insert or update) a session for a peer.
    fn store_session(&mut self, peer_id: &str, state: &SessionState) -> Result<(), CryptoError>;
}

/// Persists one-time pre-key private halves.
pub trait PreKeyStore {
    /// Load and remove a one-time pre-key by ID (consumed after use).
    fn take_prekey(&mut self, key_id: u32) -> Result<Option<OneTimePreKey>, CryptoError>;
}

/// Persists signed pre-key private halves.
pub trait SignedPreKeyStore {
    /// Load a signed pre-key by ID.
    fn load_signed_prekey(&self, key_id: u32) -> Result<Option<SignedPreKey>, CryptoError>;
}

/// Persists the local identity key pair.
pub trait IdentityKeyStore {
    /// Load the local identity key pair.
    fn get_identity(&self) -> Result<IdentityKeyPair, CryptoError>;
}

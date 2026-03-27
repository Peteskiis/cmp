use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Wrapper around `StaticSecret` that zeroizes on drop.
/// Upstream `StaticSecret` implements `Zeroize` but not `ZeroizeOnDrop`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingStaticSecret(StaticSecret);

impl ZeroizingStaticSecret {
    pub fn random() -> Self {
        Self(StaticSecret::random_from_rng(OsRng))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> x25519_dalek::SharedSecret {
        self.0.diffie_hellman(their_public)
    }

    pub fn to_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.0)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Long-term identity key pair (Ed25519 for signing, convertible to X25519 for DH).
/// Not `Clone` — secret key material should not be silently duplicated.
pub struct IdentityKeyPair {
    signing_key: SigningKey,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Convert the Ed25519 signing key to an X25519 static secret for DH.
    /// `to_scalar_bytes()` returns unclamped bytes; `StaticSecret::from()`
    /// applies clamping internally.
    pub fn to_x25519_secret(&self) -> ZeroizingStaticSecret {
        ZeroizingStaticSecret::from_bytes(self.signing_key.to_scalar_bytes())
    }

    /// Convert the Ed25519 verifying key to an X25519 public key.
    pub fn to_x25519_public(&self) -> X25519PublicKey {
        verifying_key_to_x25519(&self.verifying_key())
    }

    /// Raw Ed25519 secret key bytes (for persistence).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

// No custom Drop needed — SigningKey implements ZeroizeOnDrop with the `zeroize` feature.

/// Convert any Ed25519 verifying key to X25519 public key (Montgomery form).
pub fn verifying_key_to_x25519(vk: &VerifyingKey) -> X25519PublicKey {
    X25519PublicKey::from(vk.to_montgomery().to_bytes())
}

/// A signed pre-key: X25519 key pair + Ed25519 signature over the public key.
pub struct SignedPreKey {
    key_id: u32,
    secret: ZeroizingStaticSecret,
    public: X25519PublicKey,
    /// Ed25519 signature over `public.as_bytes()`.
    signature: ed25519_dalek::Signature,
}

impl SignedPreKey {
    /// Generate a new signed pre-key, signed by the identity key.
    pub fn generate(key_id: u32, identity: &IdentityKeyPair) -> Self {
        use ed25519_dalek::Signer;

        let secret = ZeroizingStaticSecret::random();
        let public = secret.to_public();
        let signature = identity.signing_key().sign(public.as_bytes());

        Self {
            key_id,
            secret,
            public,
            signature,
        }
    }

    pub fn from_parts(
        key_id: u32,
        secret_bytes: [u8; 32],
        public_bytes: [u8; 32],
        signature: ed25519_dalek::Signature,
    ) -> Self {
        Self {
            key_id,
            secret: ZeroizingStaticSecret::from_bytes(secret_bytes),
            public: X25519PublicKey::from(public_bytes),
            signature,
        }
    }

    pub const fn key_id(&self) -> u32 {
        self.key_id
    }

    pub const fn secret(&self) -> &ZeroizingStaticSecret {
        &self.secret
    }

    pub const fn public(&self) -> &X25519PublicKey {
        &self.public
    }

    pub const fn signature(&self) -> &ed25519_dalek::Signature {
        &self.signature
    }

    /// Verify the signature using the signer's identity key.
    pub fn verify(&self, identity_key: &VerifyingKey) -> Result<(), CryptoError> {
        use ed25519_dalek::Verifier;

        identity_key
            .verify(self.public.as_bytes(), &self.signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// A one-time pre-key: X25519 key pair, consumed after a single X3DH handshake.
pub struct OneTimePreKey {
    key_id: u32,
    secret: ZeroizingStaticSecret,
    public: X25519PublicKey,
}

impl OneTimePreKey {
    pub fn generate(key_id: u32) -> Self {
        let secret = ZeroizingStaticSecret::random();
        let public = secret.to_public();
        Self {
            key_id,
            secret,
            public,
        }
    }

    pub fn from_parts(key_id: u32, secret_bytes: [u8; 32], public_bytes: [u8; 32]) -> Self {
        Self {
            key_id,
            secret: ZeroizingStaticSecret::from_bytes(secret_bytes),
            public: X25519PublicKey::from(public_bytes),
        }
    }

    pub const fn key_id(&self) -> u32 {
        self.key_id
    }

    pub const fn secret(&self) -> &ZeroizingStaticSecret {
        &self.secret
    }

    pub const fn public(&self) -> &X25519PublicKey {
        &self.public
    }
}

/// Generate a batch of one-time pre-keys with sequential IDs starting from `start_id`.
///
/// # Errors
///
/// Returns an error if `start_id + count` overflows `u32`.
pub fn generate_one_time_prekeys(
    start_id: u32,
    count: u32,
) -> Result<Vec<OneTimePreKey>, crate::error::CryptoError> {
    let end = start_id.checked_add(count).ok_or_else(|| {
        crate::error::CryptoError::InvalidBundle("pre-key ID range overflow".into())
    })?;
    Ok((start_id..end).map(OneTimePreKey::generate).collect())
}

/// Ephemeral X25519 key pair for X3DH — zeroized after use.
pub struct EphemeralKeyPair {
    secret: ZeroizingStaticSecret,
    public: X25519PublicKey,
}

impl EphemeralKeyPair {
    pub fn generate() -> Self {
        let secret = ZeroizingStaticSecret::random();
        let public = secret.to_public();
        Self { secret, public }
    }

    pub const fn secret(&self) -> &ZeroizingStaticSecret {
        &self.secret
    }

    pub const fn public(&self) -> &X25519PublicKey {
        &self.public
    }
}

/// Serializable form of a ratchet key pair (for session persistence).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RatchetKeyPair {
    pub(crate) secret_bytes: [u8; 32],
    pub(crate) public_bytes: [u8; 32],
}

impl RatchetKeyPair {
    pub fn generate() -> Self {
        let secret = ZeroizingStaticSecret::random();
        let public = secret.to_public();
        Self {
            secret_bytes: secret.to_bytes(),
            public_bytes: public.to_bytes(),
        }
    }

    pub fn to_secret(&self) -> ZeroizingStaticSecret {
        ZeroizingStaticSecret::from_bytes(self.secret_bytes)
    }

    pub fn to_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.public_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_key_generation() {
        let ik = IdentityKeyPair::generate();
        let vk = ik.verifying_key();
        // Verifying key should be derivable from signing key
        assert_eq!(vk, ik.signing_key().verifying_key());
    }

    #[test]
    fn identity_key_roundtrip() {
        let ik = IdentityKeyPair::generate();
        let bytes = ik.to_bytes();
        let restored = IdentityKeyPair::from_bytes(&bytes);
        assert_eq!(ik.verifying_key(), restored.verifying_key());
    }

    #[test]
    fn ed25519_to_x25519_conversion() {
        let ik = IdentityKeyPair::generate();
        let x_secret = ik.to_x25519_secret();
        let x_public_from_secret = x_secret.to_public();
        let x_public_from_vk = ik.to_x25519_public();
        // Both conversion paths should produce the same X25519 public key
        assert_eq!(x_public_from_secret.as_bytes(), x_public_from_vk.as_bytes());
    }

    #[test]
    fn dh_key_agreement() {
        let alice = ZeroizingStaticSecret::random();
        let bob = ZeroizingStaticSecret::random();
        let alice_pub = alice.to_public();
        let bob_pub = bob.to_public();

        let shared_ab = alice.diffie_hellman(&bob_pub);
        let shared_ba = bob.diffie_hellman(&alice_pub);
        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    #[test]
    fn signed_prekey_generation_and_verification() {
        let ik = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(0, &ik);
        assert!(spk.verify(&ik.verifying_key()).is_ok());
    }

    #[test]
    fn signed_prekey_wrong_identity_fails() {
        let ik = IdentityKeyPair::generate();
        let other_ik = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(0, &ik);
        assert!(spk.verify(&other_ik.verifying_key()).is_err());
    }

    #[test]
    fn one_time_prekey_batch() {
        let keys = generate_one_time_prekeys(10, 5).expect("gen");
        assert_eq!(keys.len(), 5);
        for (i, key) in keys.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let expected_id = 10 + i as u32;
            assert_eq!(key.key_id(), expected_id);
            // Public key should match what the secret derives
            let derived = key.secret().to_public();
            assert_eq!(key.public().as_bytes(), derived.as_bytes());
        }
    }

    #[test]
    fn ratchet_keypair_roundtrip() {
        let kp = RatchetKeyPair::generate();
        let secret = kp.to_secret();
        let public = kp.to_public();
        assert_eq!(secret.to_public().as_bytes(), public.as_bytes());
    }

    #[test]
    fn one_time_prekey_overflow_returns_error() {
        assert!(generate_one_time_prekeys(u32::MAX, 1).is_err());
        assert!(generate_one_time_prekeys(u32::MAX - 5, 10).is_err());
    }
}

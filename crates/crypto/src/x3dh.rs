use ed25519_dalek::{Verifier, VerifyingKey};
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
use crate::kdf::{HKDF_INFO_X3DH, hkdf_expand};
use crate::keys::{
    EphemeralKeyPair, IdentityKeyPair, OneTimePreKey, SignedPreKey, verifying_key_to_x25519,
};

/// 0xFF * 32 domain separator prepended to IKM per the Signal X3DH spec.
const X3DH_DOMAIN_SEPARATOR: [u8; 32] = [0xFF; 32];

/// Zero salt for X3DH HKDF per the Signal spec.
const X3DH_SALT: [u8; 32] = [0u8; 32];

/// X3DH output from the initiator (Alice).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X3dhInitResult {
    pub shared_secret: [u8; 32],
    #[zeroize(skip)]
    pub ephemeral_public: X25519PublicKey,
}

/// The public keys from Bob's pre-key bundle that Alice needs for X3DH.
pub struct PeerPreKeyBundle {
    pub identity_key: VerifyingKey,
    pub signed_prekey: X25519PublicKey,
    pub signed_prekey_id: u32,
    pub signed_prekey_signature: ed25519_dalek::Signature,
    pub one_time_prekey: Option<(u32, X25519PublicKey)>,
}

/// Alice initiates X3DH with Bob's pre-key bundle.
///
/// Performs 3 or 4 DH operations depending on whether a one-time pre-key
/// is available, then derives a shared secret via HKDF.
///
/// # Errors
///
/// Returns an error if the signed pre-key signature is invalid.
pub fn alice_initiate(
    alice_identity: &IdentityKeyPair,
    bob_bundle: &PeerPreKeyBundle,
) -> Result<X3dhInitResult, CryptoError> {
    bob_bundle
        .identity_key
        .verify(
            bob_bundle.signed_prekey.as_bytes(),
            &bob_bundle.signed_prekey_signature,
        )
        .map_err(|_| CryptoError::InvalidSignature)?;

    let ephemeral = EphemeralKeyPair::generate();
    let alice_x25519_secret = alice_identity.to_x25519_secret();
    let bob_x25519_identity = verifying_key_to_x25519(&bob_bundle.identity_key);

    let dh1 = alice_x25519_secret.diffie_hellman(&bob_bundle.signed_prekey);
    let dh2 = ephemeral.secret().diffie_hellman(&bob_x25519_identity);
    let dh3 = ephemeral.secret().diffie_hellman(&bob_bundle.signed_prekey);
    let dh4 = bob_bundle
        .one_time_prekey
        .as_ref()
        .map(|(_, opk)| ephemeral.secret().diffie_hellman(opk));

    let shared_secret = derive_x3dh_secret(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(x25519_dalek::SharedSecret::as_bytes),
    )?;

    Ok(X3dhInitResult {
        shared_secret,
        ephemeral_public: *ephemeral.public(),
    })
}

/// Bob responds to Alice's X3DH initiation.
///
/// # Errors
///
/// Returns an error if KDF derivation fails.
pub fn bob_respond(
    bob_identity: &IdentityKeyPair,
    bob_signed_prekey: &SignedPreKey,
    bob_one_time_prekey: Option<&OneTimePreKey>,
    alice_identity_key: &VerifyingKey,
    alice_ephemeral_key: &X25519PublicKey,
) -> Result<[u8; 32], CryptoError> {
    let alice_x25519_identity = verifying_key_to_x25519(alice_identity_key);
    let bob_x25519_secret = bob_identity.to_x25519_secret();

    let dh1 = bob_signed_prekey
        .secret()
        .diffie_hellman(&alice_x25519_identity);
    let dh2 = bob_x25519_secret.diffie_hellman(alice_ephemeral_key);
    let dh3 = bob_signed_prekey
        .secret()
        .diffie_hellman(alice_ephemeral_key);
    let dh4 = bob_one_time_prekey.map(|pk| pk.secret().diffie_hellman(alice_ephemeral_key));

    derive_x3dh_secret(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(x25519_dalek::SharedSecret::as_bytes),
    )
}

/// Build IKM from DH outputs and derive shared secret via HKDF.
/// Centralizes the domain separator, concatenation, KDF call, and zeroization.
fn derive_x3dh_secret(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
) -> Result<[u8; 32], CryptoError> {
    // Zeroizing<Vec> ensures DH shared secrets are wiped even on early return from hkdf_expand
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 32 * 4));
    ikm.extend_from_slice(&X3DH_DOMAIN_SEPARATOR);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(dh4_bytes) = dh4 {
        ikm.extend_from_slice(dh4_bytes);
    }

    let mut output = [0u8; 32];
    hkdf_expand(&X3DH_SALT, &ikm, HKDF_INFO_X3DH, &mut output)?;
    Ok(output)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKeyPair, SignedPreKey, generate_one_time_prekeys};

    fn setup_bob() -> (IdentityKeyPair, SignedPreKey, Vec<OneTimePreKey>) {
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(0, &bob_ik);
        let bob_opks = generate_one_time_prekeys(0, 5).expect("gen opks");
        (bob_ik, bob_spk, bob_opks)
    }

    fn bob_bundle(
        bob_ik: &IdentityKeyPair,
        bob_spk: &SignedPreKey,
        opk: Option<&OneTimePreKey>,
    ) -> PeerPreKeyBundle {
        PeerPreKeyBundle {
            identity_key: bob_ik.verifying_key(),
            signed_prekey: *bob_spk.public(),
            signed_prekey_id: bob_spk.key_id(),
            signed_prekey_signature: *bob_spk.signature(),
            one_time_prekey: opk.map(|k| (k.key_id(), *k.public())),
        }
    }

    #[test]
    fn x3dh_with_opk_produces_matching_secrets() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, bob_opks) = setup_bob();

        let bundle = bob_bundle(&bob_ik, &bob_spk, Some(&bob_opks[0]));
        let alice_result = alice_initiate(&alice_ik, &bundle).expect("alice_initiate");

        let bob_secret = bob_respond(
            &bob_ik,
            &bob_spk,
            Some(&bob_opks[0]),
            &alice_ik.verifying_key(),
            &alice_result.ephemeral_public,
        )
        .expect("bob_respond");

        assert_eq!(alice_result.shared_secret, bob_secret);
        assert_ne!(alice_result.shared_secret, [0u8; 32]);
    }

    #[test]
    fn x3dh_without_opk_produces_matching_secrets() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, _) = setup_bob();

        let bundle = bob_bundle(&bob_ik, &bob_spk, None);
        let alice_result = alice_initiate(&alice_ik, &bundle).expect("alice_initiate");

        let bob_secret = bob_respond(
            &bob_ik,
            &bob_spk,
            None,
            &alice_ik.verifying_key(),
            &alice_result.ephemeral_public,
        )
        .expect("bob_respond");

        assert_eq!(alice_result.shared_secret, bob_secret);
    }

    #[test]
    fn x3dh_with_vs_without_opk_differ() {
        let alice_ik = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, bob_opks) = setup_bob();

        let r1 = alice_initiate(
            &alice_ik,
            &bob_bundle(&bob_ik, &bob_spk, Some(&bob_opks[0])),
        )
        .expect("with opk");
        let r2 =
            alice_initiate(&alice_ik, &bob_bundle(&bob_ik, &bob_spk, None)).expect("without opk");

        assert_ne!(r1.shared_secret, r2.shared_secret);
    }

    #[test]
    fn invalid_spk_signature_rejected() {
        let alice_ik = IdentityKeyPair::generate();
        let (_bob_ik, bob_spk, _) = setup_bob();
        let wrong_ik = IdentityKeyPair::generate();

        let bundle = PeerPreKeyBundle {
            identity_key: wrong_ik.verifying_key(),
            signed_prekey: *bob_spk.public(),
            signed_prekey_id: bob_spk.key_id(),
            signed_prekey_signature: *bob_spk.signature(),
            one_time_prekey: None,
        };

        assert!(matches!(
            alice_initiate(&alice_ik, &bundle),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn different_alice_identities_produce_different_secrets() {
        let alice1 = IdentityKeyPair::generate();
        let alice2 = IdentityKeyPair::generate();
        let (bob_ik, bob_spk, _) = setup_bob();

        let bundle = bob_bundle(&bob_ik, &bob_spk, None);

        let r1 = alice_initiate(&alice1, &bundle).expect("alice1");
        let r2 = alice_initiate(&alice2, &bundle).expect("alice2");

        assert_ne!(r1.shared_secret, r2.shared_secret);
    }
}

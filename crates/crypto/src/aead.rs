use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};

use crate::error::CryptoError;
use crate::kdf::derive_message_keys;

/// Encrypt plaintext using a message key with deterministic nonce from HKDF.
///
/// `aad` is typically the serialized ratchet header — authenticated but not encrypted.
///
/// # Errors
///
/// Returns `CryptoError::EncryptionFailed` on failure.
pub fn encrypt(
    message_key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (cipher, nonce) = prepare_cipher(message_key)?;
    cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt ciphertext using a message key with deterministic nonce from HKDF.
///
/// `aad` must match exactly what was passed during encryption.
///
/// # Errors
///
/// Returns `CryptoError::DecryptionFailed` if ciphertext was tampered, AAD doesn't match,
/// or the message key is wrong.
pub fn decrypt(
    message_key: &[u8; 32],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (cipher, nonce) = prepare_cipher(message_key)?;
    cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Shared cipher setup: derive keys from message key, construct AES-256-GCM cipher + nonce.
fn prepare_cipher(
    message_key: &[u8; 32],
) -> Result<
    (
        Aes256Gcm,
        aes_gcm::aead::generic_array::GenericArray<u8, aes_gcm::aead::generic_array::typenum::U12>,
    ),
    CryptoError,
> {
    let keys = derive_message_keys(message_key)?;
    let cipher =
        Aes256Gcm::new_from_slice(&keys.aes_key).map_err(|_| CryptoError::EncryptionFailed)?;
    let nonce = *Nonce::from_slice(&keys.nonce);
    Ok((cipher, nonce))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mk = [0x42; 32];
        let pt = b"hello, encrypted world!";
        let aad = b"ratchet-header";

        let ct = encrypt(&mk, pt, aad).expect("encrypt");
        assert_ne!(ct, pt);

        let decrypted = decrypt(&mk, &ct, aad).expect("decrypt");
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mk = [0x42; 32];
        let mut ct = encrypt(&mk, b"secret", b"hdr").expect("encrypt");
        if let Some(byte) = ct.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt(&mk, &ct, b"hdr").is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        let mk = [0x42; 32];
        let ct = encrypt(&mk, b"secret", b"correct").expect("encrypt");
        assert!(decrypt(&mk, &ct, b"wrong").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(&[0x42; 32], b"secret", b"hdr").expect("encrypt");
        assert!(decrypt(&[0x43; 32], &ct, b"hdr").is_err());
    }

    #[test]
    fn empty_plaintext_works() {
        let mk = [0x42; 32];
        let ct = encrypt(&mk, b"", b"hdr").expect("encrypt");
        let pt = decrypt(&mk, &ct, b"hdr").expect("decrypt");
        assert!(pt.is_empty());
    }

    #[test]
    fn empty_aad_works() {
        let mk = [0x42; 32];
        let ct = encrypt(&mk, b"msg", b"").expect("encrypt");
        let pt = decrypt(&mk, &ct, b"").expect("decrypt");
        assert_eq!(pt, b"msg");
    }

    #[test]
    fn deterministic_encryption() {
        let mk = [0x42; 32];
        let ct1 = encrypt(&mk, b"hello", b"hdr").expect("encrypt");
        let ct2 = encrypt(&mk, b"hello", b"hdr").expect("encrypt");
        assert_eq!(ct1, ct2);
    }
}

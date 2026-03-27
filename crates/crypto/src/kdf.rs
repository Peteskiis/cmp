use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

// Protocol-level HKDF info strings — centralized to prevent typos.
pub(crate) const HKDF_INFO_RATCHET: &[u8] = b"CMP_RATCHET";
pub(crate) const HKDF_INFO_MSG_KEY: &[u8] = b"CMP_MsgKey";
pub(crate) const HKDF_INFO_X3DH: &[u8] = b"CMP_X3DH";

/// Root key + chain key output from `kdf_rk`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKeyOutput {
    pub(crate) root_key: [u8; 32],
    pub(crate) chain_key: [u8; 32],
}

/// Chain key ratchet output from `kdf_ck`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChainKeyOutput {
    pub(crate) chain_key: [u8; 32],
    pub(crate) message_key: [u8; 32],
}

/// Message encryption keys derived from a message key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKeys {
    pub(crate) aes_key: [u8; 32],
    pub(crate) nonce: [u8; 12],
}

/// Shared HKDF-SHA-256 expand helper. Writes into `out`, returns `CryptoError::KdfFailure` on error.
pub(crate) fn hkdf_expand(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).map_err(|_| CryptoError::KdfFailure)
}

/// Root key KDF — derives new root key and chain key from a DH output.
///
/// # Errors
///
/// Returns an error if HKDF expansion fails (should not happen with valid inputs).
pub fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<RootKeyOutput, CryptoError> {
    let mut output = [0u8; 64];
    hkdf_expand(root_key, dh_output, HKDF_INFO_RATCHET, &mut output)?;
    let mut result = RootKeyOutput {
        root_key: [0u8; 32],
        chain_key: [0u8; 32],
    };
    result.root_key.copy_from_slice(&output[..32]);
    result.chain_key.copy_from_slice(&output[32..]);
    output.zeroize();
    Ok(result)
}

/// `message_key = HMAC-SHA-256(chain_key, 0x01)`
/// `new_chain_key = HMAC-SHA-256(chain_key, 0x02)`
///
/// # Errors
///
/// Returns an error if HMAC construction fails (should not happen with valid inputs).
pub fn kdf_ck(chain_key: &[u8; 32]) -> Result<ChainKeyOutput, CryptoError> {
    let message_key = hmac_sha256(chain_key, &[0x01])?;
    let new_chain_key = hmac_sha256(chain_key, &[0x02])?;
    Ok(ChainKeyOutput {
        chain_key: new_chain_key,
        message_key,
    })
}

/// Derive AES-256-GCM key and nonce from a message key.
///
/// Outputs 44 bytes: 32-byte AES key + 12-byte GCM nonce.
/// Safe because each message key is used exactly once (deterministic nonce, no reuse).
///
/// # Errors
///
/// Returns an error if HKDF expansion fails (should not happen with valid inputs).
pub fn derive_message_keys(message_key: &[u8; 32]) -> Result<MessageKeys, CryptoError> {
    let mut output = [0u8; 44];
    // message_key as IKM, empty salt — matches Signal convention
    hkdf_expand(&[0u8; 32], message_key, HKDF_INFO_MSG_KEY, &mut output)?;
    let mut result = MessageKeys {
        aes_key: [0u8; 32],
        nonce: [0u8; 12],
    };
    result.aes_key.copy_from_slice(&output[..32]);
    result.nonce.copy_from_slice(&output[32..44]);
    output.zeroize();
    Ok(result)
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| CryptoError::KdfFailure)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn kdf_rk_produces_distinct_outputs() {
        let result = kdf_rk(&[0xAA; 32], &[0xBB; 32]).expect("kdf_rk");
        assert_ne!(result.root_key, result.chain_key);
        assert_ne!(result.root_key, [0u8; 32]);
    }

    #[test]
    fn kdf_rk_is_deterministic() {
        let r1 = kdf_rk(&[0x11; 32], &[0x22; 32]).expect("kdf_rk");
        let r2 = kdf_rk(&[0x11; 32], &[0x22; 32]).expect("kdf_rk");
        assert_eq!(r1.root_key, r2.root_key);
        assert_eq!(r1.chain_key, r2.chain_key);
    }

    #[test]
    fn kdf_rk_different_inputs_produce_different_outputs() {
        let r1 = kdf_rk(&[0x11; 32], &[0x22; 32]).expect("kdf_rk");
        let r2 = kdf_rk(&[0x11; 32], &[0x33; 32]).expect("kdf_rk");
        assert_ne!(r1.root_key, r2.root_key);
    }

    #[test]
    fn kdf_ck_produces_distinct_outputs() {
        let result = kdf_ck(&[0xCC; 32]).expect("kdf_ck");
        assert_ne!(result.chain_key, result.message_key);
        assert_ne!(result.chain_key, [0xCC; 32]);
    }

    #[test]
    fn kdf_ck_is_deterministic() {
        let r1 = kdf_ck(&[0xDD; 32]).expect("kdf_ck");
        let r2 = kdf_ck(&[0xDD; 32]).expect("kdf_ck");
        assert_eq!(r1.chain_key, r2.chain_key);
        assert_eq!(r1.message_key, r2.message_key);
    }

    #[test]
    fn kdf_ck_chain_advances() {
        let r1 = kdf_ck(&[0xEE; 32]).expect("kdf_ck");
        let r2 = kdf_ck(&r1.chain_key).expect("kdf_ck");
        let r3 = kdf_ck(&r2.chain_key).expect("kdf_ck");
        assert_ne!(r1.message_key, r2.message_key);
        assert_ne!(r2.message_key, r3.message_key);
    }

    #[test]
    fn derive_message_keys_produces_valid_output() {
        let keys = derive_message_keys(&[0xFF; 32]).expect("derive");
        assert_ne!(keys.aes_key, [0u8; 32]);
        assert_ne!(keys.nonce, [0u8; 12]);
    }

    #[test]
    fn derive_message_keys_is_deterministic() {
        let k1 = derive_message_keys(&[0x42; 32]).expect("derive");
        let k2 = derive_message_keys(&[0x42; 32]).expect("derive");
        assert_eq!(k1.aes_key, k2.aes_key);
        assert_eq!(k1.nonce, k2.nonce);
    }
}

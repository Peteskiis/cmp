#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid pre-key bundle: {0}")]
    InvalidBundle(String),

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("no session found for peer")]
    NoSession,

    #[error("skipped message key limit exceeded")]
    SkippedKeyLimitExceeded,

    #[error("KDF expansion failed")]
    KdfFailure,

    #[error("message counter exhausted (u32::MAX messages in a single chain)")]
    MessageCounterExhausted,
}

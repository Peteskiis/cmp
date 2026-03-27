use crate::types::UserId;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    #[error("user not found: {0}")]
    UserNotFound(UserId),

    #[error("no pre-keys available for user: {0}")]
    NoPreKeysAvailable(UserId),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("invalid message format: {0}")]
    InvalidFormat(String),

    #[error("rate limited")]
    RateLimited,

    #[error("message too large")]
    MessageTooLarge,

    #[error("unsupported protocol version {got} (max supported: {max_supported})")]
    UnsupportedVersion { got: u32, max_supported: u32 },
}

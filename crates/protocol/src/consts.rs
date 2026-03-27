/// Maximum one-time pre-keys in a single upload or registration.
pub const MAX_PREKEYS_PER_UPLOAD: usize = 200;

/// Maximum message IDs in a single Ack batch.
pub const MAX_ACK_BATCH: usize = 1000;

/// Maximum queued messages delivered in a single `QueuedMessages` response.
pub const MAX_QUEUED_MESSAGES: usize = 1000;

/// Maximum plaintext message size in bytes (before encryption).
pub const MAX_PLAINTEXT_BYTES: usize = 256 * 1024;

/// Maximum ciphertext field size in bytes (base64-encoded, accounts for
/// encryption overhead + base64 expansion).
pub const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;

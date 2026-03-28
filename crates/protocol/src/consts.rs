/// Maximum one-time pre-keys in a single upload or registration.
pub const MAX_PREKEYS_PER_UPLOAD: usize = 200;

/// Maximum message IDs in a single Ack batch.
pub const MAX_ACK_BATCH: usize = 1000;

/// Maximum queued messages delivered in a single `QueuedMessages` response.
pub const MAX_QUEUED_MESSAGES: usize = 1000;

/// Maximum ciphertext field size in bytes (base64-encoded, accounts for
/// encryption overhead + base64 expansion).
pub const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;

/// Maximum queued messages per recipient before the server rejects new sends.
pub const MAX_QUEUE_PER_USER: usize = 10_000;

/// Maximum message IDs in a single read receipt batch.
pub const MAX_RECEIPT_BATCH: usize = 100;

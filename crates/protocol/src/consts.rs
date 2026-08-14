/// Maximum one-time pre-keys in a single upload or registration.
pub const MAX_PREKEYS_PER_UPLOAD: usize = 200;

/// Target number of one-time prekeys generated during registration/replenishment.
pub const PREKEY_TARGET: usize = 100;

/// Maximum server-side one-time prekey inventory per user.
pub const MAX_PREKEYS_PER_USER: usize = 200;
pub const ONE_TIME_PREKEY_PUBLIC_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;
pub const ONE_TIME_PREKEY_PRIVATE_RETENTION_SECS: u64 = 61 * 24 * 60 * 60;
pub const ONE_TIME_PREKEY_RESERVATION_SECS: u64 = 24 * 60 * 60;

/// Signed pre-keys rotate monthly. Implementations retain prior keys long enough
/// to decrypt first messages accepted during the previous key's lifetime.
pub const SIGNED_PREKEY_ROTATION_SECS: u64 = 30 * 24 * 60 * 60;

/// Maximum message IDs in a single Ack batch.
pub const MAX_ACK_BATCH: usize = 1000;

/// Maximum queued messages delivered during one authentication cycle.
pub const MAX_QUEUED_MESSAGES: usize = 1000;

/// Maximum queued messages in one WebSocket response. The byte limit below
/// will usually produce smaller pages for large ciphertexts.
pub const MAX_QUEUED_MESSAGES_PER_PAGE: usize = 64;

/// Maximum encoded size of a queued-delivery WebSocket response. This keeps a
/// full-size ciphertext deliverable while bounding each allocation and frame.
pub const MAX_QUEUED_PAGE_BYTES: usize = MAX_CIPHERTEXT_BYTES + 16 * 1024;

/// Maximum ciphertext field size in bytes (base64-encoded, accounts for
/// encryption overhead + base64 expansion).
pub const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;

/// Maximum queued messages per recipient before the server rejects new sends.
pub const MAX_QUEUE_PER_USER: usize = 10_000;

/// Maximum message IDs in a single read receipt batch.
pub const MAX_RECEIPT_BATCH: usize = 100;

/// Maximum durable outbound items retained by one client.
pub const MAX_PENDING_OUTBOUND_ITEMS: usize = 1000;

/// Maximum encoded ciphertext bytes retained in the durable client outbox.
pub const MAX_PENDING_OUTBOUND_BYTES: usize = 64 * 1024 * 1024;

/// Maximum unconfirmed processed-message IDs retained by one client.
pub const MAX_PROCESSED_MESSAGES: usize = 10_000;

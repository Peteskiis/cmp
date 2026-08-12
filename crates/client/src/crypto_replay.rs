use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ProcessedMessage {
    pub(super) pending_plaintext: Option<String>,
    pub(super) processed_at: u64,
}

pub(super) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(super) fn prune_processed(
    processed: &mut HashMap<String, HashMap<String, ProcessedMessage>>,
    now: u64,
) {
    // Server queue GC runs at 30 days. The extra day covers the full redelivery window.
    let cutoff = now.saturating_sub(RETENTION_SECS);
    processed.retain(|_, messages| {
        messages.retain(|_, message| message.processed_at >= cutoff);
        !messages.is_empty()
    });
}

pub(super) const RETENTION_SECS: u64 = 31 * 24 * 60 * 60;

pub(super) fn validate_peer_ids<T>(by_peer: &HashMap<String, T>) -> anyhow::Result<()> {
    for peer_id in by_peer.keys() {
        if protocol::UserId::new(peer_id).is_err() {
            anyhow::bail!("invalid peer ID in persisted cryptographic state");
        }
    }
    Ok(())
}

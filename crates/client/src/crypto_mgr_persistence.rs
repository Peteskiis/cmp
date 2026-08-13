use base64::Engine;

use super::{
    B64, CoreStateRef, CryptoManager, HashMap, OneTimePreKey, PeerSession, PendingOutbound,
    SignedPreKey, StoredOpk, StoredSpk, crypto_store,
};

impl CryptoManager {
    pub(super) fn persist_state(&self) -> anyhow::Result<()> {
        self.check_persistence()?;
        self.store.save_core(&self.core_state())
    }

    pub(super) fn persist_outbound(&self, outbound: &PendingOutbound) -> anyhow::Result<()> {
        self.check_persistence()?;
        self.store
            .save_core_and_enqueue(&self.core_state(), &outbound.correlation_id(), outbound)
    }

    pub(super) fn persist_decrypt(
        &self,
        peer_id: &str,
        message_id: Option<&str>,
    ) -> anyhow::Result<()> {
        self.check_persistence()?;
        let Some(message_id) = message_id else {
            return self.store.save_core(&self.core_state());
        };
        let processed = self
            .processed_messages
            .get(peer_id)
            .and_then(|messages| messages.get(message_id))
            .ok_or_else(|| anyhow::anyhow!("processed message marker missing"))?;
        self.store.save_core_and_processed(
            &self.core_state(),
            &crypto_store::ProcessedRow {
                peer_id: peer_id.to_owned(),
                message_id: message_id.to_owned(),
                pending_plaintext: processed.pending_plaintext.clone(),
                processed_at: processed.processed_at,
            },
        )
    }

    pub(super) fn core_state(&self) -> CoreStateRef<'_> {
        let signed_prekey = self.stored_spk.as_ref().map(|spk| StoredSpk {
            key_id: spk.key_id(),
            secret_bytes: spk.secret().to_bytes(),
            public_bytes: spk.public().to_bytes(),
            signature_b64: B64.encode(spk.signature().to_bytes()),
        });
        let one_time_prekeys = self
            .stored_opks
            .values()
            .map(|opk| StoredOpk {
                key_id: opk.key_id(),
                secret_bytes: opk.secret().to_bytes(),
                public_bytes: opk.public().to_bytes(),
            })
            .collect();
        CoreStateRef {
            signed_prekey,
            one_time_prekeys,
            sessions: &self.sessions,
            next_one_time_prekey_id: self.next_one_time_prekey_id,
        }
    }

    pub(super) fn check_persistence(&self) -> anyhow::Result<()> {
        if self.fail_persistence {
            return Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "injected disk-full failure",
            )
            .into());
        }
        Ok(())
    }
}

pub(super) fn decode_stored_spk(stored: Option<StoredSpk>) -> anyhow::Result<Option<SignedPreKey>> {
    let Some(stored) = stored else {
        return Ok(None);
    };
    let sig_bytes = B64.decode(&stored.signature_b64)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("corrupt signed prekey signature"))?;
    Ok(Some(SignedPreKey::from_parts(
        stored.key_id,
        stored.secret_bytes,
        stored.public_bytes,
        ed25519_dalek::Signature::from_bytes(&sig_arr),
    )))
}

pub(super) fn decode_stored_opks(stored: Vec<StoredOpk>) -> HashMap<u32, OneTimePreKey> {
    stored
        .into_iter()
        .map(|stored| {
            (
                stored.key_id,
                OneTimePreKey::from_parts(stored.key_id, stored.secret_bytes, stored.public_bytes),
            )
        })
        .collect()
}

pub(super) fn restore_entry(
    sessions: &mut HashMap<String, PeerSession>,
    peer_id: &str,
    previous: Option<PeerSession>,
) {
    if let Some(session) = previous {
        sessions.insert(peer_id.to_owned(), session);
    } else {
        sessions.remove(peer_id);
    }
}

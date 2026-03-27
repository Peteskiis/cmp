use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::kdf::{kdf_ck, kdf_rk};
use crate::keys::RatchetKeyPair;

/// Maximum number of skipped message keys stored per session.
const MAX_SKIP: u32 = 1000;

/// Double Ratchet message header — sent unencrypted, used as AAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Sender's current DH ratchet public key (32 bytes).
    pub ratchet_key: [u8; 32],
    /// Number of messages sent in the previous sending chain.
    pub previous_chain_length: u32,
    /// Message index within the current sending chain.
    pub message_number: u32,
}

impl RatchetHeader {
    /// Serialize to fixed-size bytes for use as AAD in AEAD.
    /// No heap allocation — this is called on every encrypt/decrypt.
    pub fn to_aad(&self) -> [u8; 40] {
        let mut aad = [0u8; 40];
        aad[..32].copy_from_slice(&self.ratchet_key);
        aad[32..36].copy_from_slice(&self.previous_chain_length.to_be_bytes());
        aad[36..40].copy_from_slice(&self.message_number.to_be_bytes());
        aad
    }
}

/// Encrypted message output from the ratchet.
pub struct RatchetMessage {
    pub header: RatchetHeader,
    pub ciphertext: Vec<u8>,
}

/// Persistent session state for the Double Ratchet.
///
/// # Clone safety
///
/// `Clone` is used internally for snapshot/rollback on decrypt failure.
/// **Callers must not clone a session and encrypt on both copies** — this would
/// produce two messages with the same key+nonce, which is catastrophic for AES-GCM.
/// Treat session state as logically move-only.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionState {
    root_key: [u8; 32],
    our_ratchet: RatchetKeyPair,
    their_ratchet_key: Option<[u8; 32]>,
    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,
    send_count: u32,
    recv_count: u32,
    previous_send_count: u32,
    /// `(ratchet_key, message_number) -> message_key`.
    #[serde(with = "skipped_keys_serde")]
    skipped: SkippedKeysMap,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut ck) = self.sending_chain_key {
            ck.zeroize();
        }
        if let Some(ref mut ck) = self.receiving_chain_key {
            ck.zeroize();
        }
        for key in self.skipped.values_mut() {
            key.zeroize();
        }
    }
}

/// Initialize a session as Alice (the initiator).
///
/// Alice has already performed X3DH and knows the shared secret and Bob's
/// signed pre-key (used as Bob's initial ratchet public key).
pub fn initialize_alice(
    shared_secret: [u8; 32],
    bob_ratchet_public: &X25519PublicKey,
) -> Result<SessionState, CryptoError> {
    let our_ratchet = RatchetKeyPair::generate();
    let our_secret = our_ratchet.to_secret();
    let dh_output = our_secret.diffie_hellman(bob_ratchet_public);
    let rk_out = kdf_rk(&shared_secret, dh_output.as_bytes())?;

    Ok(SessionState {
        root_key: rk_out.root_key,
        our_ratchet,
        their_ratchet_key: Some(bob_ratchet_public.to_bytes()),
        sending_chain_key: Some(rk_out.chain_key),
        receiving_chain_key: None,
        send_count: 0,
        recv_count: 0,
        previous_send_count: 0,
        skipped: HashMap::new(),
    })
}

/// Initialize a session as Bob (the responder).
///
/// Bob uses his signed pre-key as the initial ratchet key pair.
pub fn initialize_bob(shared_secret: [u8; 32], bob_ratchet: RatchetKeyPair) -> SessionState {
    SessionState {
        root_key: shared_secret,
        our_ratchet: bob_ratchet,
        their_ratchet_key: None,
        sending_chain_key: None,
        receiving_chain_key: None,
        send_count: 0,
        recv_count: 0,
        previous_send_count: 0,
        skipped: HashMap::new(),
    }
}

/// Encrypt a plaintext message using the Double Ratchet.
///
/// # Errors
///
/// Returns an error if the sending chain is not initialized or the message
/// counter has been exhausted (`u32::MAX` messages in a single chain).
pub fn encrypt(state: &mut SessionState, plaintext: &[u8]) -> Result<RatchetMessage, CryptoError> {
    // Pre-compute new count before any state mutation — fail fast on exhaustion
    let new_send_count = state
        .send_count
        .checked_add(1)
        .ok_or(CryptoError::MessageCounterExhausted)?;

    let chain_key = state
        .sending_chain_key
        .as_ref()
        .ok_or(CryptoError::NoSession)?;

    let ck_out = kdf_ck(chain_key)?;
    let header = RatchetHeader {
        ratchet_key: state.our_ratchet.public_bytes,
        previous_chain_length: state.previous_send_count,
        message_number: state.send_count,
    };

    let aad = header.to_aad();
    let ciphertext = crate::aead::encrypt(&ck_out.message_key, plaintext, &aad)?;

    // Commit state only after all fallible operations succeed
    state.sending_chain_key = Some(ck_out.chain_key);
    state.send_count = new_send_count;

    Ok(RatchetMessage { header, ciphertext })
}

/// Decrypt a message using the Double Ratchet.
///
/// State is only committed after successful AEAD authentication. If a forged
/// message fails decryption, the session state is rolled back — this prevents
/// a malicious peer from corrupting the session with crafted headers.
///
/// # Errors
///
/// Returns an error if decryption fails, the message key is not found,
/// the skipped key limit is exceeded, or the message counter is exhausted.
pub fn decrypt(
    state: &mut SessionState,
    header: &RatchetHeader,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Check if this is a skipped message (already authenticated in a prior step)
    let skip_key = (header.ratchet_key, header.message_number);
    if let Some(mut message_key) = state.skipped.remove(&skip_key) {
        let aad = header.to_aad();
        let result = crate::aead::decrypt(&message_key, ciphertext, &aad);
        if result.is_err() {
            // Re-insert the key since decryption failed — don't consume it
            state.skipped.insert(skip_key, message_key);
        }
        message_key.zeroize();
        return result;
    }

    // Snapshot state before mutations so we can roll back on AEAD failure.
    // This prevents a forged message from permanently corrupting the session.
    let snapshot = state.clone();

    let try_decrypt = try_decrypt_inner(state, header, ciphertext);

    if try_decrypt.is_err() {
        // Roll back all state mutations
        *state = snapshot;
    }

    try_decrypt
}

/// Inner decrypt logic that mutates state. Called by `decrypt` which handles rollback.
fn try_decrypt_inner(
    state: &mut SessionState,
    header: &RatchetHeader,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let need_dh_step = state.their_ratchet_key.as_ref() != Some(&header.ratchet_key);

    if need_dh_step {
        if state.receiving_chain_key.is_some() {
            skip_message_keys(state, state.recv_count, header.previous_chain_length)?;
        }

        let their_public = X25519PublicKey::from(header.ratchet_key);
        let our_secret = state.our_ratchet.to_secret();
        let dh_output = our_secret.diffie_hellman(&their_public);
        let rk_out = kdf_rk(&state.root_key, dh_output.as_bytes())?;

        state.root_key = rk_out.root_key;
        state.their_ratchet_key = Some(header.ratchet_key);
        state.receiving_chain_key = Some(rk_out.chain_key);
        state.recv_count = 0;

        state.previous_send_count = state.send_count;
        state.send_count = 0;
        state.our_ratchet = RatchetKeyPair::generate();
        let new_secret = state.our_ratchet.to_secret();
        let dh_output2 = new_secret.diffie_hellman(&their_public);
        let rk_out2 = kdf_rk(&state.root_key, dh_output2.as_bytes())?;
        state.root_key = rk_out2.root_key;
        state.sending_chain_key = Some(rk_out2.chain_key);
    }

    skip_message_keys(state, state.recv_count, header.message_number)?;

    let chain_key = state
        .receiving_chain_key
        .as_ref()
        .ok_or(CryptoError::NoSession)?;
    let ck_out = kdf_ck(chain_key)?;

    // Attempt AEAD decryption — this is the authentication check
    let aad = header.to_aad();
    let plaintext = crate::aead::decrypt(&ck_out.message_key, ciphertext, &aad)?;

    // Only commit state after successful authentication.
    // recv_count must track the next expected message number — after decrypting
    // message N (potentially after a gap), it becomes N+1, not old_count+1.
    state.receiving_chain_key = Some(ck_out.chain_key);
    state.recv_count = header
        .message_number
        .checked_add(1)
        .ok_or(CryptoError::MessageCounterExhausted)?;

    Ok(plaintext)
}

/// Skip and store message keys from `current` to `until` (exclusive).
fn skip_message_keys(
    state: &mut SessionState,
    current: u32,
    until: u32,
) -> Result<(), CryptoError> {
    if until <= current {
        return Ok(());
    }

    let to_skip = until - current;

    // Use u64 arithmetic to prevent wrapping overflow that could bypass the limit.
    // skipped.len() is bounded by MAX_SKIP so it fits in u32, but we use u64 for
    // the addition to avoid any possibility of wrapping.
    let total = u64::from(to_skip) + state.skipped.len() as u64;
    if total > u64::from(MAX_SKIP) {
        return Err(CryptoError::SkippedKeyLimitExceeded);
    }

    let Some(their_key) = state.their_ratchet_key else {
        return Ok(());
    };

    let Some(mut chain_key) = state.receiving_chain_key else {
        return Ok(());
    };

    for i in current..until {
        let ck_out = kdf_ck(&chain_key)?;
        state.skipped.insert((their_key, i), ck_out.message_key);
        chain_key = ck_out.chain_key;
    }
    state.receiving_chain_key = Some(chain_key);

    Ok(())
}

type SkippedKeysMap = HashMap<([u8; 32], u32), [u8; 32]>;

/// Serde helper for skipped message keys map. JSON doesn't support tuple keys,
/// so we serialize as a vec of structs.
mod skipped_keys_serde {
    use super::SkippedKeysMap;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Entry {
        ratchet_key: [u8; 32],
        message_number: u32,
        message_key: [u8; 32],
    }

    pub fn serialize<S>(map: &SkippedKeysMap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries: Vec<Entry> = map
            .iter()
            .map(|((rk, mn), mk)| Entry {
                ratchet_key: *rk,
                message_number: *mn,
                message_key: *mk,
            })
            .collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SkippedKeysMap, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries: Vec<Entry> = Vec::deserialize(deserializer)?;
        if entries.len() > super::MAX_SKIP as usize {
            return Err(serde::de::Error::custom(
                "skipped key count exceeds MAX_SKIP",
            ));
        }
        Ok(entries
            .into_iter()
            .map(|e| ((e.ratchet_key, e.message_number), e.message_key))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKeyPair, SignedPreKey};

    fn setup_session() -> (SessionState, SessionState) {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(0, &bob_ik);

        let bob_ratchet =
            RatchetKeyPair::from_bytes(bob_spk.secret().to_bytes(), bob_spk.public().to_bytes());

        let bundle = crate::x3dh::PeerPreKeyBundle {
            identity_key: bob_ik.verifying_key(),
            signed_prekey: *bob_spk.public(),
            signed_prekey_id: 0,
            signed_prekey_signature: *bob_spk.signature(),
            one_time_prekey: None,
        };
        let x3dh_result = crate::x3dh::alice_initiate(&alice_ik, &bundle).expect("x3dh");
        let bob_secret = crate::x3dh::bob_respond(
            &bob_ik,
            &bob_spk,
            None,
            &alice_ik.verifying_key(),
            &x3dh_result.ephemeral_public,
        )
        .expect("x3dh bob");

        let alice_session =
            initialize_alice(x3dh_result.shared_secret, bob_spk.public()).expect("init alice");
        let bob_session = initialize_bob(bob_secret, bob_ratchet);

        (alice_session, bob_session)
    }

    #[test]
    fn basic_exchange() {
        let (mut alice, mut bob) = setup_session();

        let msg1 = encrypt(&mut alice, b"hello bob").expect("encrypt");
        let pt1 = decrypt(&mut bob, &msg1.header, &msg1.ciphertext).expect("decrypt");
        assert_eq!(pt1, b"hello bob");

        let msg2 = encrypt(&mut bob, b"hello alice").expect("encrypt");
        let pt2 = decrypt(&mut alice, &msg2.header, &msg2.ciphertext).expect("decrypt");
        assert_eq!(pt2, b"hello alice");
    }

    #[test]
    fn multi_message_exchange() {
        let (mut alice, mut bob) = setup_session();

        let m1 = encrypt(&mut alice, b"msg 1").expect("e");
        let m2 = encrypt(&mut alice, b"msg 2").expect("e");
        let m3 = encrypt(&mut alice, b"msg 3").expect("e");

        assert_eq!(
            decrypt(&mut bob, &m1.header, &m1.ciphertext).expect("d"),
            b"msg 1"
        );
        assert_eq!(
            decrypt(&mut bob, &m2.header, &m2.ciphertext).expect("d"),
            b"msg 2"
        );
        assert_eq!(
            decrypt(&mut bob, &m3.header, &m3.ciphertext).expect("d"),
            b"msg 3"
        );

        let m4 = encrypt(&mut bob, b"reply 1").expect("e");
        let m5 = encrypt(&mut bob, b"reply 2").expect("e");
        assert_eq!(
            decrypt(&mut alice, &m4.header, &m4.ciphertext).expect("d"),
            b"reply 1"
        );
        assert_eq!(
            decrypt(&mut alice, &m5.header, &m5.ciphertext).expect("d"),
            b"reply 2"
        );

        let m6 = encrypt(&mut alice, b"final").expect("e");
        assert_eq!(
            decrypt(&mut bob, &m6.header, &m6.ciphertext).expect("d"),
            b"final"
        );
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut alice, mut bob) = setup_session();

        let m1 = encrypt(&mut alice, b"first").expect("e");
        let m2 = encrypt(&mut alice, b"second").expect("e");
        let m3 = encrypt(&mut alice, b"third").expect("e");

        assert_eq!(
            decrypt(&mut bob, &m3.header, &m3.ciphertext).expect("d"),
            b"third"
        );
        assert_eq!(
            decrypt(&mut bob, &m1.header, &m1.ciphertext).expect("d"),
            b"first"
        );
        assert_eq!(
            decrypt(&mut bob, &m2.header, &m2.ciphertext).expect("d"),
            b"second"
        );
    }

    #[test]
    fn session_state_serialization() {
        let (alice, _bob) = setup_session();

        let json = serde_json::to_string(&alice).expect("serialize");
        let restored: SessionState = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(alice.root_key, restored.root_key);
        assert_eq!(alice.send_count, restored.send_count);
    }

    #[test]
    fn restored_session_works() {
        let (mut alice, mut bob) = setup_session();

        let m1 = encrypt(&mut alice, b"before save").expect("e");
        assert_eq!(
            decrypt(&mut bob, &m1.header, &m1.ciphertext).expect("d"),
            b"before save"
        );

        let json = serde_json::to_string(&alice).expect("serialize");
        let mut restored: SessionState = serde_json::from_str(&json).expect("deserialize");

        let m2 = encrypt(&mut bob, b"after restore").expect("e");
        assert_eq!(
            decrypt(&mut restored, &m2.header, &m2.ciphertext).expect("d"),
            b"after restore"
        );

        let m3 = encrypt(&mut restored, b"from restored").expect("e");
        assert_eq!(
            decrypt(&mut bob, &m3.header, &m3.ciphertext).expect("d"),
            b"from restored"
        );
    }

    #[test]
    fn tampered_ciphertext_rejected_without_corrupting_session() {
        let (mut alice, mut bob) = setup_session();

        // Send a legitimate message first to establish the receiving chain
        let m1 = encrypt(&mut alice, b"legit 1").expect("e");
        assert_eq!(
            decrypt(&mut bob, &m1.header, &m1.ciphertext).expect("d"),
            b"legit 1"
        );

        // Forge a message with a tampered ciphertext
        let mut forged = encrypt(&mut alice, b"will be tampered").expect("e");
        if let Some(byte) = forged.ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt(&mut bob, &forged.header, &forged.ciphertext).is_err());

        // Session must still work after the forged message was rejected
        let m3 = encrypt(&mut alice, b"legit after forge").expect("e");
        assert_eq!(
            decrypt(&mut bob, &m3.header, &m3.ciphertext).expect("d"),
            b"legit after forge"
        );
    }

    #[test]
    fn forged_dh_ratchet_does_not_corrupt_session() {
        let (mut alice, mut bob) = setup_session();

        let m1 = encrypt(&mut alice, b"setup").expect("e");
        assert_eq!(
            decrypt(&mut bob, &m1.header, &m1.ciphertext).expect("d"),
            b"setup"
        );

        // Bob replies to trigger a DH ratchet step
        let m2 = encrypt(&mut bob, b"reply").expect("e");
        assert_eq!(
            decrypt(&mut alice, &m2.header, &m2.ciphertext).expect("d"),
            b"reply"
        );

        // Alice sends another — Bob will need a DH ratchet step to decrypt
        let m3 = encrypt(&mut alice, b"after ratchet").expect("e");

        // Forge a message with Alice's ratchet key but garbage ciphertext.
        // This forces Bob through the DH ratchet step code path before AEAD fails.
        let forged_header = RatchetHeader {
            ratchet_key: m3.header.ratchet_key,
            previous_chain_length: m3.header.previous_chain_length,
            message_number: 999,
        };
        assert!(decrypt(&mut bob, &forged_header, b"garbage").is_err());

        // Bob's session must still decrypt the real message
        assert_eq!(
            decrypt(&mut bob, &m3.header, &m3.ciphertext).expect("d"),
            b"after ratchet"
        );
    }

    #[test]
    fn replay_rejected() {
        let (mut alice, mut bob) = setup_session();

        let msg = encrypt(&mut alice, b"once only").expect("e");
        assert_eq!(
            decrypt(&mut bob, &msg.header, &msg.ciphertext).expect("d"),
            b"once only"
        );

        // Replaying the same message should fail — the message key was consumed
        assert!(decrypt(&mut bob, &msg.header, &msg.ciphertext).is_err());
    }

    #[test]
    fn wrong_session_fails() {
        let (mut alice1, _) = setup_session();
        let (_, mut bob2) = setup_session();

        let msg = encrypt(&mut alice1, b"wrong session").expect("e");
        assert!(decrypt(&mut bob2, &msg.header, &msg.ciphertext).is_err());
    }

    #[test]
    fn skipped_key_limit_exceeded() {
        let (mut alice, mut bob) = setup_session();

        let mut messages = Vec::new();
        for i in 0..MAX_SKIP + 2 {
            let msg = encrypt(&mut alice, format!("msg {i}").as_bytes()).expect("e");
            messages.push(msg);
        }

        let last = messages.last().expect("last");
        assert!(matches!(
            decrypt(&mut bob, &last.header, &last.ciphertext),
            Err(CryptoError::SkippedKeyLimitExceeded)
        ),);
    }

    /// Receive message 3 first (skipping 0-2), then receive 4 in-order.
    /// This catches a bug where recv_count increments by 1 instead of
    /// tracking message_number+1 after a gap.
    #[test]
    fn in_order_after_gap() {
        let (mut alice, mut bob) = setup_session();

        let m0 = encrypt(&mut alice, b"zero").expect("e");
        let m1 = encrypt(&mut alice, b"one").expect("e");
        let m2 = encrypt(&mut alice, b"two").expect("e");
        let m3 = encrypt(&mut alice, b"three").expect("e");
        let m4 = encrypt(&mut alice, b"four").expect("e");

        // Deliver m3 first — skips keys for 0, 1, 2
        assert_eq!(
            decrypt(&mut bob, &m3.header, &m3.ciphertext).expect("d"),
            b"three"
        );
        // Deliver m4 in-order after the gap
        assert_eq!(
            decrypt(&mut bob, &m4.header, &m4.ciphertext).expect("d"),
            b"four"
        );
        // Now deliver the skipped messages out of order
        assert_eq!(
            decrypt(&mut bob, &m1.header, &m1.ciphertext).expect("d"),
            b"one"
        );
        assert_eq!(
            decrypt(&mut bob, &m0.header, &m0.ciphertext).expect("d"),
            b"zero"
        );
        assert_eq!(
            decrypt(&mut bob, &m2.header, &m2.ciphertext).expect("d"),
            b"two"
        );
    }

    /// Out-of-order delivery across a DH ratchet step: Alice sends m1, m2 on
    /// chain A, Bob receives m1 and replies (triggering DH ratchet), Alice
    /// sends m3 on chain B, Bob receives m3 first then late m2 from chain A.
    #[test]
    fn out_of_order_across_dh_ratchet() {
        let (mut alice, mut bob) = setup_session();

        let m1 = encrypt(&mut alice, b"first").expect("e");
        let m2 = encrypt(&mut alice, b"second").expect("e");

        // Bob receives m1 and replies — triggers DH ratchet
        assert_eq!(
            decrypt(&mut bob, &m1.header, &m1.ciphertext).expect("d"),
            b"first"
        );
        let reply = encrypt(&mut bob, b"reply").expect("e");
        assert_eq!(
            decrypt(&mut alice, &reply.header, &reply.ciphertext).expect("d"),
            b"reply"
        );

        // Alice sends on new chain (after DH ratchet)
        let m3 = encrypt(&mut alice, b"third").expect("e");

        // Bob receives m3 first (new chain), then late m2 (old chain)
        assert_eq!(
            decrypt(&mut bob, &m3.header, &m3.ciphertext).expect("d"),
            b"third"
        );
        assert_eq!(
            decrypt(&mut bob, &m2.header, &m2.ciphertext).expect("d"),
            b"second"
        );
    }

    #[test]
    fn send_counter_exhaustion() {
        let (mut alice, _bob) = setup_session();
        alice.send_count = u32::MAX;
        let chain_key_before = alice.sending_chain_key;
        assert!(matches!(
            encrypt(&mut alice, b"should fail"),
            Err(CryptoError::MessageCounterExhausted)
        ));
        // State must be unchanged after the error — no chain key advancement
        assert_eq!(alice.sending_chain_key, chain_key_before);
        assert_eq!(alice.send_count, u32::MAX);
    }

    /// Bob's sending chain is None until he receives Alice's first message.
    #[test]
    fn bob_cannot_send_before_receiving() {
        let (_alice, mut bob) = setup_session();
        assert!(matches!(
            encrypt(&mut bob, b"eager"),
            Err(CryptoError::NoSession)
        ));
    }

    #[test]
    fn recv_counter_exhaustion() {
        let (mut alice, mut bob) = setup_session();

        // Send a normal message so Bob has a receiving chain
        let m1 = encrypt(&mut alice, b"setup").expect("e");
        assert_eq!(
            decrypt(&mut bob, &m1.header, &m1.ciphertext).expect("d"),
            b"setup"
        );

        // Craft a message with message_number = u32::MAX
        let mut m2 = encrypt(&mut alice, b"overflow").expect("e");
        m2.header.message_number = u32::MAX;

        // Decryption should fail (AEAD will reject the tampered header via AAD mismatch,
        // but even if it somehow passed, checked_add would catch it). The session
        // must survive due to snapshot/rollback.
        assert!(decrypt(&mut bob, &m2.header, &m2.ciphertext).is_err());

        // Session still works after the failed attempt
        let m3 = encrypt(&mut alice, b"still works").expect("e");
        assert_eq!(
            decrypt(&mut bob, &m3.header, &m3.ciphertext).expect("d"),
            b"still works"
        );
    }
}

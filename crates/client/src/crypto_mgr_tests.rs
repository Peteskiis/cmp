use super::*;
use tempfile::TempDir;

/// Set up Alice and Bob `CryptoManager` instances with registration keys.
fn setup_alice_and_bob() -> (CryptoManager, CryptoManager, TempDir, TempDir) {
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    let mut alice = CryptoManager::load_or_generate(alice_dir.path()).unwrap();
    let mut bob = CryptoManager::load_or_generate(bob_dir.path()).unwrap();

    // Bob registers — persist SPK + OPKs
    let bob_spk = SignedPreKey::generate(0, bob.identity());
    let bob_opks = crypto::keys::generate_one_time_prekeys(0, 5).unwrap();
    bob.persist_registration_keys(&bob_spk, &bob_opks).unwrap();

    // Alice gets Bob's bundle (simulating server fetch)
    let bundle = protocol::PreKeyBundle {
        identity_key: B64.encode(bob.identity().verifying_key().as_bytes()),
        signed_prekey: B64.encode(bob_spk.public().as_bytes()),
        signed_prekey_id: bob_spk.key_id(),
        signed_prekey_signature: B64.encode(bob_spk.signature().to_bytes()),
        one_time_prekey: Some(protocol::OneTimePreKey {
            key_id: bob_opks[0].key_id(),
            public_key: B64.encode(bob_opks[0].public().as_bytes()),
        }),
    };
    alice.init_session_from_bundle("bob", &bundle).unwrap();

    (alice, bob, alice_dir, bob_dir)
}

#[test]
fn alice_encrypt_bob_decrypt_prekey() {
    let (mut alice, mut bob, _a_dir, _b_dir) = setup_alice_and_bob();

    let envelope = alice.encrypt("bob", b"hello bob").unwrap();
    // Should be a PreKey message
    assert!(matches!(envelope.header, MessageHeader::PreKey { .. }));

    let plaintext = bob.decrypt("alice", &envelope).unwrap();
    assert_eq!(plaintext, b"hello bob");

    // Bob should now have a session
    assert!(bob.has_session("alice"));
    // OPK should be consumed
    assert!(bob.stored_opks.is_empty() || bob.stored_opks.len() == 4);
}

#[test]
fn forged_prekey_no_orphan_session_no_opk_consumed() {
    let (_alice, mut bob, _a_dir, _b_dir) = setup_alice_and_bob();
    let opk_count_before = bob.stored_opks.len();

    // Forge a PreKey message with garbage ciphertext
    let forged = EncryptedEnvelope {
        version: 1,
        header: MessageHeader::PreKey {
            sender_identity_key: B64.encode([1u8; 32]),
            sender_ephemeral_key: B64.encode([2u8; 32]),
            recipient_signed_prekey_id: 0,
            recipient_one_time_prekey_id: Some(0),
            ratchet: ProtoRatchetHeader {
                ratchet_key: B64.encode([3u8; 32]),
                previous_chain_length: 0,
                message_number: 0,
            },
        },
        ciphertext: B64.encode(b"garbage"),
    };

    let result = bob.decrypt("mallory", &forged);
    assert!(result.is_err());
    // No orphan session
    assert!(!bob.has_session("mallory"));
    // OPK not consumed
    assert_eq!(bob.stored_opks.len(), opk_count_before);
}

#[test]
fn existing_session_not_destroyed_by_prekey() {
    let (mut alice, mut bob, _a_dir, _b_dir) = setup_alice_and_bob();

    // Alice sends first message — Bob creates session
    let env1 = alice.encrypt("bob", b"first").unwrap();
    bob.decrypt("alice", &env1).unwrap();
    assert!(bob.has_session("alice"));

    // Forge a PreKey from "alice" with garbage — should NOT destroy session
    let forged = EncryptedEnvelope {
        version: 1,
        header: MessageHeader::PreKey {
            sender_identity_key: B64.encode([9u8; 32]),
            sender_ephemeral_key: B64.encode([9u8; 32]),
            recipient_signed_prekey_id: 0,
            recipient_one_time_prekey_id: None,
            ratchet: ProtoRatchetHeader {
                ratchet_key: B64.encode([9u8; 32]),
                previous_chain_length: 0,
                message_number: 0,
            },
        },
        ciphertext: B64.encode(b"fake"),
    };
    let _ = bob.decrypt("alice", &forged); // should fail but NOT nuke session

    // Session still works
    assert!(bob.has_session("alice"));
    let env2 = alice.encrypt("bob", b"second").unwrap();
    let pt2 = bob.decrypt("alice", &env2).unwrap();
    assert_eq!(pt2, b"second");
}

#[test]
fn missing_opk_returns_error() {
    let (_alice, mut bob, _a_dir, _b_dir) = setup_alice_and_bob();

    // PreKey message claiming OPK 999 which Bob doesn't have
    let forged = EncryptedEnvelope {
        version: 1,
        header: MessageHeader::PreKey {
            sender_identity_key: B64.encode([1u8; 32]),
            sender_ephemeral_key: B64.encode([2u8; 32]),
            recipient_signed_prekey_id: 0,
            recipient_one_time_prekey_id: Some(999),
            ratchet: ProtoRatchetHeader {
                ratchet_key: B64.encode([3u8; 32]),
                previous_chain_length: 0,
                message_number: 0,
            },
        },
        ciphertext: B64.encode(b"anything"),
    };

    let result = bob.decrypt("someone", &forged);
    assert!(result.is_err());
}

#[test]
fn persistence_roundtrip() {
    let (mut alice, mut bob, _a_dir, b_dir) = setup_alice_and_bob();

    // Alice sends, Bob decrypts
    let env1 = alice.encrypt("bob", b"persist me").unwrap();
    bob.decrypt("alice", &env1).unwrap();

    // Reload Bob from disk
    let mut bob2 = CryptoManager::load_or_generate(b_dir.path()).unwrap();
    assert!(bob2.has_session("alice"));

    // Alice sends another message — Bob2 should decrypt it
    let env2 = alice.encrypt("bob", b"after reload").unwrap();
    let pt2 = bob2.decrypt("alice", &env2).unwrap();
    assert_eq!(pt2, b"after reload");
}

#[test]
fn disk_full_during_encrypt_does_not_release_or_advance_ciphertext() {
    let (mut alice, mut bob, a_dir, _b_dir) = setup_alice_and_bob();
    alice.fail_persistence = true;

    let result = alice.encrypt("bob", b"send after restart");
    assert!(matches!(result, Err(CryptoError::Persistence(_))));
    drop(alice);

    let mut restarted = CryptoManager::load_or_generate(a_dir.path()).unwrap();
    let envelope = restarted.encrypt("bob", b"send after restart").unwrap();
    assert!(matches!(envelope.header, MessageHeader::PreKey { .. }));
    assert_eq!(
        bob.decrypt("alice", &envelope).unwrap(),
        b"send after restart"
    );
}

#[test]
fn disk_full_during_decrypt_preserves_session_and_opk_for_restart() {
    let (mut alice, mut bob, _a_dir, b_dir) = setup_alice_and_bob();
    let envelope = alice.encrypt("bob", b"retry after restart").unwrap();
    let opk_count = bob.stored_opks.len();
    bob.fail_persistence = true;

    let result = bob.decrypt("alice", &envelope);
    assert!(matches!(result, Err(CryptoError::Persistence(_))));
    assert!(!bob.has_session("alice"));
    assert_eq!(bob.stored_opks.len(), opk_count);
    drop(bob);

    let mut restarted = CryptoManager::load_or_generate(b_dir.path()).unwrap();
    assert_eq!(
        restarted.decrypt("alice", &envelope).unwrap(),
        b"retry after restart"
    );
}

#[test]
fn outbound_ciphertext_survives_restart_until_server_confirmation() {
    let (mut alice, mut bob, a_dir, _b_dir) = setup_alice_and_bob();
    let message_id = MessageId::new();
    let second_message_id = MessageId::new();
    let recipient = UserId::new("bob").unwrap();
    alice
        .encrypt_message("bob", &recipient, &message_id, b"durable send")
        .unwrap();
    alice
        .encrypt_message("bob", &recipient, &second_message_id, b"ordered retry")
        .unwrap();
    drop(alice);

    let mut restarted = CryptoManager::load_or_generate(a_dir.path()).unwrap();
    let pending = restarted.pending_messages();
    assert_eq!(pending.len(), 2);
    let ClientMessage::SendMessage {
        message_id: pending_id,
        envelope,
        ..
    } = &pending[0]
    else {
        panic!("expected pending message");
    };
    assert_eq!(pending_id, &message_id);
    assert_eq!(bob.decrypt("alice", envelope).unwrap(), b"durable send");
    let ClientMessage::SendMessage {
        message_id: pending_id,
        envelope,
        ..
    } = &pending[1]
    else {
        panic!("expected pending message");
    };
    assert_eq!(pending_id, &second_message_id);
    assert_eq!(bob.decrypt("alice", envelope).unwrap(), b"ordered retry");

    restarted.confirm_message_sent(&message_id).unwrap();
    restarted.confirm_message_sent(&second_message_id).unwrap();
    drop(restarted);
    let confirmed = CryptoManager::load_or_generate(a_dir.path()).unwrap();
    assert!(confirmed.pending_messages().is_empty());
}

#[test]
fn processed_message_is_reacknowledged_without_redecrypting_after_restart() {
    let (mut alice, mut bob, _a_dir, b_dir) = setup_alice_and_bob();
    let message_id = MessageId::new();
    let envelope = alice.encrypt("bob", b"ack after restart").unwrap();
    assert!(matches!(
        bob.decrypt_message_to_text("alice", &message_id, &envelope),
        InboundDecrypt::Pending(ref text) if text == "ack after restart"
    ));
    drop(bob);

    let mut restarted = CryptoManager::load_or_generate(b_dir.path()).unwrap();
    assert!(matches!(
        restarted.decrypt_message_to_text("alice", &message_id, &envelope),
        InboundDecrypt::Pending(ref text) if text == "ack after restart"
    ));
    restarted
        .confirm_inbound_stored("alice", &message_id)
        .unwrap();
    drop(restarted);
    let mut restarted = CryptoManager::load_or_generate(b_dir.path()).unwrap();
    assert!(matches!(
        restarted.decrypt_message_to_text("alice", &message_id, &envelope),
        InboundDecrypt::Duplicate
    ));
}

#[test]
fn read_receipt_survives_restart_until_server_confirmation() {
    let (mut alice, mut bob, a_dir, _b_dir) = setup_alice_and_bob();
    let received_id = MessageId::new();
    let recipient = UserId::new("bob").unwrap();
    alice
        .encrypt_read_receipt("bob", &recipient, std::slice::from_ref(&received_id))
        .unwrap();
    drop(alice);

    let mut restarted = CryptoManager::load_or_generate(a_dir.path()).unwrap();
    let pending = restarted.pending_messages();
    assert_eq!(pending.len(), 1);
    let ClientMessage::SendReadReceipt { envelope, .. } = &pending[0] else {
        panic!("expected pending read receipt");
    };
    let plaintext = bob.decrypt("alice", envelope).unwrap();
    let ids: Vec<String> = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(ids, [received_id.to_string()]);

    restarted.confirm_read_receipt_sent().unwrap();
    drop(restarted);
    assert!(
        CryptoManager::load_or_generate(a_dir.path())
            .unwrap()
            .pending_messages()
            .is_empty()
    );
}

#[test]
fn processed_message_retention_is_bounded_to_server_gc_window() {
    let mut processed = HashMap::from([(
        "alice".to_owned(),
        HashMap::from([
            (
                "expired".to_owned(),
                ProcessedMessage {
                    pending_plaintext: None,
                    processed_at: 1,
                },
            ),
            (
                "current".to_owned(),
                ProcessedMessage {
                    pending_plaintext: None,
                    processed_at: 40 * 24 * 60 * 60,
                },
            ),
        ]),
    )]);
    prune_processed(&mut processed, 40 * 24 * 60 * 60);
    let messages = processed.get("alice").unwrap();
    assert!(!messages.contains_key("expired"));
    assert!(messages.contains_key("current"));
}

#[test]
fn registration_persistence_failure_restores_memory_and_disk() {
    let directory = tempfile::tempdir().unwrap();
    let mut manager = CryptoManager::load_or_generate(directory.path()).unwrap();
    let spk = SignedPreKey::generate(0, manager.identity());
    let opks = crypto::keys::generate_one_time_prekeys(0, 2).unwrap();
    manager.fail_persistence = true;

    assert!(manager.persist_registration_keys(&spk, &opks).is_err());
    assert!(manager.needs_registration());
    drop(manager);
    assert!(
        CryptoManager::load_or_generate(directory.path())
            .unwrap()
            .needs_registration()
    );
}

#[test]
fn session_initialization_failure_restores_memory_and_disk() {
    let (mut alice, bob, a_dir, _b_dir) = setup_alice_and_bob();
    let spk = bob.stored_spk.as_ref().unwrap();
    let bundle = protocol::PreKeyBundle {
        identity_key: B64.encode(bob.identity().verifying_key().as_bytes()),
        signed_prekey: B64.encode(spk.public().as_bytes()),
        signed_prekey_id: spk.key_id(),
        signed_prekey_signature: B64.encode(spk.signature().to_bytes()),
        one_time_prekey: None,
    };
    alice.fail_persistence = true;

    assert!(matches!(
        alice.init_session_from_bundle("carol", &bundle),
        Err(CryptoError::Persistence(_))
    ));
    assert!(!alice.has_session("carol"));
    drop(alice);
    assert!(
        !CryptoManager::load_or_generate(a_dir.path())
            .unwrap()
            .has_session("carol")
    );
}

#[test]
fn established_decrypt_failure_restores_memory_and_disk() {
    let (mut alice, mut bob, _a_dir, b_dir) = setup_alice_and_bob();
    let first = alice.encrypt("bob", b"first").unwrap();
    bob.decrypt("alice", &first).unwrap();
    let second = alice.encrypt("bob", b"second").unwrap();
    bob.fail_persistence = true;

    assert!(matches!(
        bob.decrypt("alice", &second),
        Err(CryptoError::Persistence(_))
    ));
    drop(bob);
    let mut restarted = CryptoManager::load_or_generate(b_dir.path()).unwrap();
    assert_eq!(restarted.decrypt("alice", &second).unwrap(), b"second");
}

#[test]
fn corrupt_persisted_state_is_not_silently_discarded() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("state.json"), b"not json").unwrap();

    assert!(CryptoManager::load_or_generate(directory.path()).is_err());
}

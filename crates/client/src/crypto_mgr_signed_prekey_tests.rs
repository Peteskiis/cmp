use super::tests::setup_alice_and_bob;
use super::*;

fn queued_rotation(manager: &CryptoManager) -> (MessageId, u32) {
    manager
        .pending_messages()
        .into_iter()
        .find_map(|message| match message {
            ClientMessage::RotateSignedPreKey {
                rotation_id,
                key_id,
                ..
            } => Some((rotation_id, key_id)),
            _ => None,
        })
        .expect("signed prekey rotation queued")
}

#[test]
#[allow(clippy::cognitive_complexity)]
fn rotation_is_durable_and_bounded() {
    let (_alice, mut bob, _alice_dir, bob_dir) = setup_alice_and_bob();
    bob.signed_prekey_rotated_at = 0;
    bob.queue_signed_prekey_rotation().unwrap();
    let (rotation_id, key_id) = queued_rotation(&bob);
    assert_eq!(key_id, 1);
    drop(bob);

    let mut bob = CryptoManager::load_or_generate(bob_dir.path()).unwrap();
    assert_eq!(bob.stored_spk.as_ref().unwrap().key_id(), 1);
    assert_eq!(bob.previous_spks[0].key_id(), 0);
    assert!(
        bob.confirm_signed_prekey_rotated(&rotation_id, true, 1)
            .unwrap()
            .is_none()
    );

    for expected_id in 2..=5 {
        bob.signed_prekey_rotated_at = 0;
        bob.queue_signed_prekey_rotation().unwrap();
        let (rotation_id, key_id) = queued_rotation(&bob);
        assert_eq!(key_id, expected_id);
        assert!(
            bob.confirm_signed_prekey_rotated(&rotation_id, true, expected_id)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(bob.stored_spk.as_ref().unwrap().key_id(), 5);
    assert_eq!(
        bob.previous_spks
            .iter()
            .map(SignedPreKey::key_id)
            .collect::<Vec<_>>(),
        vec![4, 3, 2]
    );
}

#[test]
fn first_message_decrypts_with_previous_key() {
    let (mut alice, mut bob, _alice_dir, _bob_dir) = setup_alice_and_bob();
    bob.signed_prekey_rotated_at = 0;
    bob.queue_signed_prekey_rotation().unwrap();

    let envelope = alice.encrypt("bob", b"delayed first message").unwrap();
    assert_eq!(
        bob.decrypt("alice", &envelope).unwrap(),
        b"delayed first message"
    );
}

#[test]
fn rejection_reconciles_and_survives_restart() {
    let (_alice, mut bob, _alice_dir, bob_dir) = setup_alice_and_bob();
    bob.signed_prekey_rotated_at = 0;
    bob.queue_signed_prekey_rotation().unwrap();
    let (rejected_id, rejected_key_id) = queued_rotation(&bob);
    assert_eq!(rejected_key_id, 1);

    let replacement = bob
        .confirm_signed_prekey_rotated(&rejected_id, false, 5)
        .unwrap()
        .expect("replacement rotation");
    assert!(matches!(
        replacement,
        ClientMessage::RotateSignedPreKey { key_id: 6, .. }
    ));
    drop(bob);

    let mut bob = CryptoManager::load_or_generate(bob_dir.path()).unwrap();
    let (replacement_id, replacement_key_id) = queued_rotation(&bob);
    assert_eq!(replacement_key_id, 6);
    assert_ne!(replacement_id, rejected_id);
    assert_eq!(bob.stored_spk.as_ref().unwrap().key_id(), 6);
    assert!(
        bob.confirm_signed_prekey_rotated(&replacement_id, true, 6)
            .unwrap()
            .is_none()
    );
    assert!(bob.pending_messages().is_empty());
}

#[test]
fn rejection_reconciliation_is_atomic_on_failure() {
    let (_alice, mut bob, _alice_dir, bob_dir) = setup_alice_and_bob();
    bob.signed_prekey_rotated_at = 0;
    bob.queue_signed_prekey_rotation().unwrap();
    let (rejected_id, rejected_key_id) = queued_rotation(&bob);
    assert_eq!(rejected_key_id, 1);
    bob.store.inject_replace_outbound_failure();

    assert!(
        bob.confirm_signed_prekey_rotated(&rejected_id, false, 5)
            .is_err()
    );
    assert_eq!(bob.stored_spk.as_ref().unwrap().key_id(), 1);
    assert_eq!(queued_rotation(&bob).0, rejected_id);
    drop(bob);

    let mut bob = CryptoManager::load_or_generate(bob_dir.path()).unwrap();
    assert_eq!(bob.stored_spk.as_ref().unwrap().key_id(), 1);
    assert_eq!(queued_rotation(&bob).0, rejected_id);
    let replacement = bob
        .confirm_signed_prekey_rotated(&rejected_id, false, 5)
        .unwrap()
        .expect("replacement rotation");
    assert!(matches!(
        replacement,
        ClientMessage::RotateSignedPreKey { key_id: 6, .. }
    ));
}

#[test]
fn accepted_older_key_reconciles_to_server_current() {
    let (_alice, mut bob, _alice_dir, bob_dir) = setup_alice_and_bob();
    bob.signed_prekey_rotated_at = 0;
    bob.queue_signed_prekey_rotation().unwrap();
    let (older_id, older_key_id) = queued_rotation(&bob);
    assert_eq!(older_key_id, 1);

    let replacement = bob
        .confirm_signed_prekey_rotated(&older_id, true, 2)
        .unwrap()
        .expect("replacement rotation");
    assert!(matches!(
        replacement,
        ClientMessage::RotateSignedPreKey { key_id: 3, .. }
    ));
    drop(bob);

    let bob = CryptoManager::load_or_generate(bob_dir.path()).unwrap();
    assert_eq!(queued_rotation(&bob).1, 3);
    assert_eq!(bob.stored_spk.as_ref().unwrap().key_id(), 3);
}

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::Signer;
use futures::{SinkExt, StreamExt};
use protocol::{
    ClientMessage, EncryptedEnvelope, MessageId, ServerMessage, UserId,
    types::{MessageHeader, OneTimePreKey, PreKeyBundle, RatchetHeader as ProtoRatchetHeader},
};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Start a server on a random port, return the ws:// URL.
async fn start_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{addr}/ws");
    let handle = server::start_server(listener, "test-server").await.unwrap();
    (url, handle)
}

/// Connect a WebSocket client.
async fn connect(url: &str) -> (WsSink, WsStream) {
    let (ws, _) = connect_async(url).await.unwrap();
    ws.split()
}

type WsSink = futures::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>;
type WsStream = futures::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

/// Send a ClientMessage as JSON.
async fn send(sink: &mut WsSink, msg: &ClientMessage) {
    let json = serde_json::to_string(msg).unwrap();
    sink.send(Message::Text(json.into())).await.unwrap();
}

/// Receive and parse a ServerMessage.
async fn recv(stream: &mut WsStream) -> ServerMessage {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text).unwrap();
            }
            Some(Ok(Message::Ping(_))) => continue,
            other => panic!("unexpected message: {other:?}"),
        }
    }
}

fn make_identity() -> crypto::keys::IdentityKeyPair {
    crypto::keys::IdentityKeyPair::generate()
}

fn make_bundle(identity: &crypto::keys::IdentityKeyPair) -> (PreKeyBundle, Vec<OneTimePreKey>) {
    let (bundle, otks, _, _) = make_bundle_with_keys(identity);
    (bundle, otks)
}

async fn register(
    sink: &mut WsSink,
    stream: &mut WsStream,
    user: &str,
    identity: &crypto::keys::IdentityKeyPair,
) {
    let (bundle, otks) = make_bundle(identity);
    let uid = UserId::new(user).unwrap();
    send(
        sink,
        &ClientMessage::Register {
            user_id: uid,
            bundle,
            one_time_prekeys: otks,
        },
    )
    .await;
    let resp = recv(stream).await;
    assert!(
        matches!(resp, ServerMessage::AuthSuccess),
        "register failed: {resp:?}"
    );
}

async fn auth_challenge_response(
    sink: &mut WsSink,
    stream: &mut WsStream,
    user: &str,
    identity: &crypto::keys::IdentityKeyPair,
) {
    let uid = UserId::new(user).unwrap();
    send(sink, &ClientMessage::AuthChallenge { user_id: uid }).await;

    let ServerMessage::Challenge {
        nonce,
        timestamp,
        server_id,
    } = recv(stream).await
    else {
        panic!("expected Challenge");
    };

    let nonce_bytes = B64.decode(&nonce).unwrap();
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&nonce_bytes);
    signed_data.extend_from_slice(&timestamp.to_be_bytes());
    signed_data.extend_from_slice(server_id.as_bytes());

    let sig = identity.signing_key().sign(&signed_data);
    send(
        sink,
        &ClientMessage::AuthResponse {
            signature: B64.encode(sig.to_bytes()),
        },
    )
    .await;

    let resp = recv(stream).await;
    assert!(
        matches!(resp, ServerMessage::AuthSuccess),
        "auth failed: {resp:?}"
    );
}

fn dummy_envelope(text: &str) -> EncryptedEnvelope {
    EncryptedEnvelope {
        version: 1,
        header: MessageHeader::Ratchet(ProtoRatchetHeader {
            ratchet_key: B64.encode([0u8; 32]),
            previous_chain_length: 0,
            message_number: 0,
        }),
        ciphertext: B64.encode(text.as_bytes()),
    }
}

// ── Tests ──

#[tokio::test]
async fn register_and_auth() {
    let (url, _handle) = start_test_server().await;
    let identity = make_identity();

    // Register
    let (mut sink, mut stream) = connect(&url).await;
    register(&mut sink, &mut stream, "alice", &identity).await;
    drop((sink, stream));

    // Re-auth on a new connection
    let (mut sink, mut stream) = connect(&url).await;
    auth_challenge_response(&mut sink, &mut stream, "alice", &identity).await;
}

#[tokio::test]
async fn duplicate_registration_rejected() {
    let (url, _handle) = start_test_server().await;
    let identity1 = make_identity();
    let identity2 = make_identity();

    let (mut s1, mut r1) = connect(&url).await;
    register(&mut s1, &mut r1, "bob", &identity1).await;
    drop((s1, r1));

    // Second registration with different key should fail
    let (mut s2, mut r2) = connect(&url).await;
    let (bundle, otks) = make_bundle(&identity2);
    send(
        &mut s2,
        &ClientMessage::Register {
            user_id: UserId::new("bob").unwrap(),
            bundle,
            one_time_prekeys: otks,
        },
    )
    .await;
    let resp = recv(&mut r2).await;
    assert!(
        matches!(resp, ServerMessage::AuthFailure { .. }),
        "expected rejection: {resp:?}"
    );
}

#[tokio::test]
async fn send_and_receive_message() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();

    // Register both
    let (mut as1, mut ar1) = connect(&url).await;
    register(&mut as1, &mut ar1, "alice", &alice_id).await;
    drop((as1, ar1));

    let (mut bs1, mut br1) = connect(&url).await;
    register(&mut bs1, &mut br1, "bob", &bob_id).await;
    // Keep Bob connected

    // Alice connects and sends a message to Bob
    let (mut as2, mut ar2) = connect(&url).await;
    auth_challenge_response(&mut as2, &mut ar2, "alice", &alice_id).await;

    let msg_id = MessageId::new();
    send(
        &mut as2,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("bob").unwrap(),
            message_id: msg_id.clone(),
            envelope: dummy_envelope("hello bob"),
        },
    )
    .await;

    // Alice gets MessageSent + MessageDelivered (Bob is online, order may vary)
    let r1 = recv(&mut ar2).await;
    let r2 = recv(&mut ar2).await;
    assert!(
        matches!(
            &r1,
            ServerMessage::MessageSent { .. } | ServerMessage::MessageDelivered { .. }
        ),
        "unexpected: {r1:?}"
    );
    assert!(
        matches!(
            &r2,
            ServerMessage::MessageSent { .. } | ServerMessage::MessageDelivered { .. }
        ),
        "unexpected: {r2:?}"
    );

    // Bob receives the message
    let resp = recv(&mut br1).await;
    let ServerMessage::IncomingMessage(inbound) = resp else {
        panic!("expected IncomingMessage: {resp:?}");
    };
    assert_eq!(inbound.sender_id.as_str(), "alice");
    let text = String::from_utf8(B64.decode(&inbound.envelope.ciphertext).unwrap()).unwrap();
    assert_eq!(text, "hello bob");
}

#[tokio::test]
async fn offline_delivery() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();

    // Register both
    let (mut as1, mut ar1) = connect(&url).await;
    register(&mut as1, &mut ar1, "alice", &alice_id).await;

    let (mut bs1, mut br1) = connect(&url).await;
    register(&mut bs1, &mut br1, "bob", &bob_id).await;
    // Disconnect Bob
    drop((bs1, br1));

    // Alice sends while Bob is offline
    send(
        &mut as1,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("bob").unwrap(),
            message_id: MessageId::new(),
            envelope: dummy_envelope("you there?"),
        },
    )
    .await;
    let _ = recv(&mut ar1).await; // MessageSent

    // Bob reconnects — should get queued message
    let (mut bs2, mut br2) = connect(&url).await;
    auth_challenge_response(&mut bs2, &mut br2, "bob", &bob_id).await;

    let resp = recv(&mut br2).await;
    let ServerMessage::QueuedMessages { messages } = resp else {
        panic!("expected QueuedMessages: {resp:?}");
    };
    assert_eq!(messages.len(), 1);
    let text = String::from_utf8(B64.decode(&messages[0].envelope.ciphertext).unwrap()).unwrap();
    assert_eq!(text, "you there?");
}

#[tokio::test]
async fn ack_removes_from_queue() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();

    let (mut as1, mut ar1) = connect(&url).await;
    register(&mut as1, &mut ar1, "alice", &alice_id).await;

    let (mut bs1, mut br1) = connect(&url).await;
    register(&mut bs1, &mut br1, "bob", &bob_id).await;
    drop((bs1, br1)); // Bob offline

    // Alice sends
    let msg_id = MessageId::new();
    send(
        &mut as1,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("bob").unwrap(),
            message_id: msg_id.clone(),
            envelope: dummy_envelope("ack me"),
        },
    )
    .await;
    let _ = recv(&mut ar1).await;

    // Bob connects, gets message, acks it
    let (mut bs2, mut br2) = connect(&url).await;
    auth_challenge_response(&mut bs2, &mut br2, "bob", &bob_id).await;
    let resp = recv(&mut br2).await;
    let ServerMessage::QueuedMessages { messages } = resp else {
        panic!("expected QueuedMessages");
    };
    let ids: Vec<MessageId> = messages.into_iter().map(|m| m.message_id).collect();
    send(&mut bs2, &ClientMessage::Ack { message_ids: ids }).await;
    drop((bs2, br2));

    // Bob reconnects again — queue should be empty (no QueuedMessages)
    let (mut bs3, mut br3) = connect(&url).await;
    auth_challenge_response(&mut bs3, &mut br3, "bob", &bob_id).await;

    // Send a ping to Bob to flush — if there were queued messages, they'd arrive before this
    send(
        &mut as1,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("bob").unwrap(),
            message_id: MessageId::new(),
            envelope: dummy_envelope("after ack"),
        },
    )
    .await;

    let resp = recv(&mut br3).await;
    // Should be IncomingMessage (the new one), NOT QueuedMessages (the old one was acked)
    assert!(
        matches!(resp, ServerMessage::IncomingMessage(_)),
        "expected IncomingMessage, got: {resp:?}"
    );
}

#[tokio::test]
async fn prekey_bundle_fetch() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();

    let (mut as1, mut ar1) = connect(&url).await;
    register(&mut as1, &mut ar1, "alice", &alice_id).await;

    let (mut bs1, mut br1) = connect(&url).await;
    register(&mut bs1, &mut br1, "bob", &bob_id).await;

    // Alice fetches Bob's bundle
    send(
        &mut as1,
        &ClientMessage::FetchPreKeyBundle {
            target_user_id: UserId::new("bob").unwrap(),
        },
    )
    .await;

    let resp = recv(&mut ar1).await;
    let ServerMessage::PreKeyBundleResponse { user_id, bundle } = resp else {
        panic!("expected PreKeyBundleResponse: {resp:?}");
    };
    assert_eq!(user_id.as_str(), "bob");
    assert!(!bundle.identity_key.is_empty());
    assert!(!bundle.signed_prekey.is_empty());
    // Should have an OPK (Bob registered with 5)
    assert!(bundle.one_time_prekey.is_some());
}

#[tokio::test]
async fn send_to_nonexistent_user_fails() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();

    let (mut as1, mut ar1) = connect(&url).await;
    register(&mut as1, &mut ar1, "alice", &alice_id).await;

    send(
        &mut as1,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("ghost").unwrap(),
            message_id: MessageId::new(),
            envelope: dummy_envelope("hello?"),
        },
    )
    .await;

    let resp = recv(&mut ar1).await;
    // Should get an error, not MessageSent
    assert!(
        matches!(resp, ServerMessage::Error { .. }),
        "expected error: {resp:?}"
    );
}

#[tokio::test]
async fn auth_with_wrong_key_rejected() {
    let (url, _handle) = start_test_server().await;
    let real_identity = make_identity();
    let wrong_identity = make_identity();

    // Register with real key
    let (mut s1, mut r1) = connect(&url).await;
    register(&mut s1, &mut r1, "carol", &real_identity).await;
    drop((s1, r1));

    // Try to auth with a different key
    let (mut s2, mut r2) = connect(&url).await;
    let uid = UserId::new("carol").unwrap();
    send(&mut s2, &ClientMessage::AuthChallenge { user_id: uid }).await;

    let ServerMessage::Challenge {
        nonce,
        timestamp,
        server_id,
    } = recv(&mut r2).await
    else {
        panic!("expected Challenge");
    };

    // Sign with the WRONG key
    let nonce_bytes = B64.decode(&nonce).unwrap();
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&nonce_bytes);
    signed_data.extend_from_slice(&timestamp.to_be_bytes());
    signed_data.extend_from_slice(server_id.as_bytes());

    let sig = wrong_identity.signing_key().sign(&signed_data);
    send(
        &mut s2,
        &ClientMessage::AuthResponse {
            signature: B64.encode(sig.to_bytes()),
        },
    )
    .await;

    let resp = recv(&mut r2).await;
    assert!(
        matches!(resp, ServerMessage::AuthFailure { .. }),
        "expected AuthFailure with wrong key: {resp:?}"
    );
}

#[tokio::test]
async fn unauthenticated_send_rejected() {
    let (url, _handle) = start_test_server().await;

    let (mut sink, mut stream) = connect(&url).await;

    // Try to send without authenticating
    send(
        &mut sink,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("anyone").unwrap(),
            message_id: MessageId::new(),
            envelope: dummy_envelope("sneaky"),
        },
    )
    .await;

    let resp = recv(&mut stream).await;
    assert!(
        matches!(resp, ServerMessage::AuthFailure { .. }),
        "expected AuthFailure: {resp:?}"
    );
}

#[tokio::test]
async fn typing_indicator_relay() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();

    let (mut as1, mut ar1) = connect(&url).await;
    register(&mut as1, &mut ar1, "alice", &alice_id).await;

    let (mut bs1, mut br1) = connect(&url).await;
    register(&mut bs1, &mut br1, "bob", &bob_id).await;

    // Alice types to Bob
    send(
        &mut as1,
        &ClientMessage::Typing {
            recipient_id: UserId::new("bob").unwrap(),
        },
    )
    .await;

    let resp = recv(&mut br1).await;
    let ServerMessage::PeerTyping { sender_id } = resp else {
        panic!("expected PeerTyping: {resp:?}");
    };
    assert_eq!(sender_id.as_str(), "alice");
}

#[tokio::test]
async fn delivery_receipt_on_push() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();

    let (mut as1, mut ar1) = connect(&url).await;
    register(&mut as1, &mut ar1, "alice", &alice_id).await;
    drop((as1, ar1));

    let (mut bs1, mut br1) = connect(&url).await;
    register(&mut bs1, &mut br1, "bob", &bob_id).await;

    // Alice reconnects and sends to online Bob
    let (mut as2, mut ar2) = connect(&url).await;
    auth_challenge_response(&mut as2, &mut ar2, "alice", &alice_id).await;

    let msg_id = MessageId::new();
    send(
        &mut as2,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("bob").unwrap(),
            message_id: msg_id.clone(),
            envelope: dummy_envelope("hello"),
        },
    )
    .await;

    // Alice should get MessageSent AND MessageDelivered (since Bob is online)
    let r1 = recv(&mut ar2).await;
    let r2 = recv(&mut ar2).await;

    let mut got_sent = false;
    let mut got_delivered = false;
    for resp in [&r1, &r2] {
        match resp {
            ServerMessage::MessageSent { message_id: mid } => {
                assert_eq!(mid, &msg_id, "MessageSent ID mismatch");
                got_sent = true;
            }
            ServerMessage::MessageDelivered { message_ids } => {
                assert!(
                    message_ids.contains(&msg_id),
                    "MessageDelivered missing our ID"
                );
                got_delivered = true;
            }
            _ => panic!("unexpected response: {resp:?}"),
        }
    }
    assert!(got_sent, "expected MessageSent in {r1:?} or {r2:?}");
    assert!(
        got_delivered,
        "expected MessageDelivered in {r1:?} or {r2:?}"
    );
}

#[tokio::test]
async fn read_receipt_relay() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();

    let (mut as1, mut ar1) = connect(&url).await;
    register(&mut as1, &mut ar1, "alice", &alice_id).await;

    let (mut bs1, mut br1) = connect(&url).await;
    register(&mut bs1, &mut br1, "bob", &bob_id).await;

    // Bob sends a read receipt to Alice (encrypted envelope as opaque blob)
    send(
        &mut bs1,
        &ClientMessage::SendReadReceipt {
            recipient_id: UserId::new("alice").unwrap(),
            envelope: dummy_envelope("read-receipt-data"),
        },
    )
    .await;

    let resp = recv(&mut ar1).await;
    let ServerMessage::IncomingReadReceipt { sender_id, .. } = resp else {
        panic!("expected IncomingReadReceipt: {resp:?}");
    };
    assert_eq!(sender_id.as_str(), "bob");
}

// ── E2EE helpers ──

fn b64_decode_fixed<const N: usize>(s: &str) -> [u8; N] {
    let bytes = B64.decode(s).unwrap();
    bytes.try_into().unwrap()
}

fn make_bundle_with_keys(
    identity: &crypto::keys::IdentityKeyPair,
) -> (
    PreKeyBundle,
    Vec<OneTimePreKey>,
    crypto::keys::SignedPreKey,
    Vec<crypto::keys::OneTimePreKey>,
) {
    let spk = crypto::keys::SignedPreKey::generate(0, identity);
    let opks = crypto::keys::generate_one_time_prekeys(0, 5).unwrap();

    let bundle = PreKeyBundle {
        identity_key: B64.encode(identity.verifying_key().as_bytes()),
        signed_prekey: B64.encode(spk.public().as_bytes()),
        signed_prekey_id: spk.key_id(),
        signed_prekey_signature: B64.encode(spk.signature().to_bytes()),
        one_time_prekey: None,
    };

    let otks: Vec<OneTimePreKey> = opks
        .iter()
        .map(|k| OneTimePreKey {
            key_id: k.key_id(),
            public_key: B64.encode(k.public().as_bytes()),
        })
        .collect();

    (bundle, otks, spk, opks)
}

/// Consume the MessageSent + MessageDelivered responses after sending to an online peer.
/// Skips PreKeyLow notifications. Panics on unexpected message types.
async fn drain_send_responses(stream: &mut WsStream) {
    let mut got_sent = false;
    let mut got_delivered = false;
    for _ in 0..4 {
        let msg = recv(stream).await;
        match msg {
            ServerMessage::MessageSent { .. } => got_sent = true,
            ServerMessage::MessageDelivered { .. } => got_delivered = true,
            ServerMessage::PreKeyLow { .. } => continue,
            other => panic!("unexpected response in drain: {other:?}"),
        }
        if got_sent && got_delivered {
            return;
        }
    }
    assert!(got_sent, "never received MessageSent");
    assert!(got_delivered, "never received MessageDelivered");
}

// ── E2EE integration test ──

#[tokio::test]
async fn e2ee_full_roundtrip() {
    use crypto::keys::RatchetKeyPair;
    use crypto::ratchet;
    use crypto::x3dh;
    use ed25519_dalek::VerifyingKey;
    use x25519_dalek::PublicKey as X25519PublicKey;

    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();

    // ── Register both users ──
    // Alice: standard registration
    let (mut as1, mut ar1) = connect(&url).await;
    register(&mut as1, &mut ar1, "alice", &alice_id).await;
    drop((as1, ar1));

    // Bob: registration with keys retained for X3DH
    let (bob_bundle, bob_otks, bob_spk, bob_opks) = make_bundle_with_keys(&bob_id);
    let (mut bs1, mut br1) = connect(&url).await;
    let uid = UserId::new("bob").unwrap();
    send(
        &mut bs1,
        &ClientMessage::Register {
            user_id: uid,
            bundle: bob_bundle,
            one_time_prekeys: bob_otks,
        },
    )
    .await;
    let resp = recv(&mut br1).await;
    assert!(matches!(resp, ServerMessage::AuthSuccess));

    // Reconnect both for the messaging session
    let (mut as2, mut ar2) = connect(&url).await;
    auth_challenge_response(&mut as2, &mut ar2, "alice", &alice_id).await;

    // ── Alice fetches Bob's prekey bundle ──
    send(
        &mut as2,
        &ClientMessage::FetchPreKeyBundle {
            target_user_id: UserId::new("bob").unwrap(),
        },
    )
    .await;

    let ServerMessage::PreKeyBundleResponse { bundle, .. } = recv(&mut ar2).await else {
        panic!("expected PreKeyBundleResponse");
    };

    // ── Alice: X3DH + ratchet init ──
    // Convert protocol bundle → crypto PeerPreKeyBundle
    let bob_vk = VerifyingKey::from_bytes(&b64_decode_fixed::<32>(&bundle.identity_key)).unwrap();
    let bob_spk_pub = X25519PublicKey::from(b64_decode_fixed::<32>(&bundle.signed_prekey));
    let bob_sig = ed25519_dalek::Signature::from_bytes(&b64_decode_fixed::<64>(
        &bundle.signed_prekey_signature,
    ));
    let bob_otk_proto = bundle.one_time_prekey.as_ref().unwrap();
    let bob_otk_pub = X25519PublicKey::from(b64_decode_fixed::<32>(&bob_otk_proto.public_key));

    let peer_bundle = x3dh::PeerPreKeyBundle {
        identity_key: bob_vk,
        signed_prekey: bob_spk_pub,
        signed_prekey_id: bundle.signed_prekey_id,
        signed_prekey_signature: bob_sig,
        one_time_prekey: Some((bob_otk_proto.key_id, bob_otk_pub)),
    };

    let x3dh_result = x3dh::alice_initiate(&alice_id, &peer_bundle).unwrap();
    let mut alice_state =
        ratchet::initialize_alice(x3dh_result.shared_secret, &bob_spk_pub).unwrap();

    // ── Alice encrypts and sends ──
    let alice_plaintext = b"hello bob, this is real E2EE";
    let ratchet_msg = ratchet::encrypt(&mut alice_state, alice_plaintext).unwrap();

    let envelope = EncryptedEnvelope {
        version: 1,
        header: MessageHeader::PreKey {
            sender_identity_key: B64.encode(alice_id.verifying_key().as_bytes()),
            sender_ephemeral_key: B64.encode(x3dh_result.ephemeral_public.as_bytes()),
            recipient_signed_prekey_id: bundle.signed_prekey_id,
            recipient_one_time_prekey_id: Some(bob_otk_proto.key_id),
            ratchet: ProtoRatchetHeader {
                ratchet_key: B64.encode(ratchet_msg.header.ratchet_key),
                previous_chain_length: ratchet_msg.header.previous_chain_length,
                message_number: ratchet_msg.header.message_number,
            },
        },
        ciphertext: B64.encode(&ratchet_msg.ciphertext),
    };

    let msg_id = MessageId::new();
    send(
        &mut as2,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("bob").unwrap(),
            message_id: msg_id.clone(),
            envelope,
        },
    )
    .await;
    drain_send_responses(&mut ar2).await;

    // ── Bob receives and decrypts ──
    // Skip any PreKeyLow notifications before the actual message
    let inbound = loop {
        let resp = recv(&mut br1).await;
        match resp {
            ServerMessage::PreKeyLow { .. } => continue,
            ServerMessage::IncomingMessage(m) => break m,
            other => panic!("expected IncomingMessage: {other:?}"),
        }
    };
    assert_eq!(inbound.sender_id.as_str(), "alice");
    assert_eq!(inbound.message_id, msg_id);

    // Parse PreKey header
    let MessageHeader::PreKey {
        sender_identity_key,
        sender_ephemeral_key,
        recipient_one_time_prekey_id,
        ratchet: ref proto_rh,
        ..
    } = inbound.envelope.header
    else {
        panic!("expected PreKey header");
    };

    let alice_vk = VerifyingKey::from_bytes(&b64_decode_fixed::<32>(&sender_identity_key)).unwrap();
    let alice_ek = X25519PublicKey::from(b64_decode_fixed::<32>(&sender_ephemeral_key));

    // Find the OPK Bob registered
    let opk_id = recipient_one_time_prekey_id.unwrap();
    let bob_opk = bob_opks.iter().find(|k| k.key_id() == opk_id).unwrap();

    // Bob X3DH
    let bob_shared_secret =
        x3dh::bob_respond(&bob_id, &bob_spk, Some(bob_opk), &alice_vk, &alice_ek).unwrap();

    // Bob ratchet init (SPK is the initial ratchet key)
    let bob_ratchet_kp =
        RatchetKeyPair::from_bytes(bob_spk.secret().to_bytes(), bob_spk.public().to_bytes());
    let mut bob_state = ratchet::initialize_bob(bob_shared_secret, bob_ratchet_kp);

    // Decrypt
    let crypto_header = crypto::ratchet::RatchetHeader {
        ratchet_key: b64_decode_fixed::<32>(&proto_rh.ratchet_key),
        previous_chain_length: proto_rh.previous_chain_length,
        message_number: proto_rh.message_number,
    };
    let ciphertext_bytes = B64.decode(&inbound.envelope.ciphertext).unwrap();
    let decrypted = ratchet::decrypt(&mut bob_state, &crypto_header, &ciphertext_bytes).unwrap();
    assert_eq!(decrypted, alice_plaintext, "Alice → Bob decryption failed");

    // ── Bob replies (Ratchet message, no PreKey header) ──
    let bob_plaintext = b"hey alice, E2EE works!";
    let bob_ratchet_msg = ratchet::encrypt(&mut bob_state, bob_plaintext).unwrap();

    let reply_envelope = EncryptedEnvelope {
        version: 1,
        header: MessageHeader::Ratchet(ProtoRatchetHeader {
            ratchet_key: B64.encode(bob_ratchet_msg.header.ratchet_key),
            previous_chain_length: bob_ratchet_msg.header.previous_chain_length,
            message_number: bob_ratchet_msg.header.message_number,
        }),
        ciphertext: B64.encode(&bob_ratchet_msg.ciphertext),
    };

    let reply_msg_id = MessageId::new();
    send(
        &mut bs1,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("alice").unwrap(),
            message_id: reply_msg_id.clone(),
            envelope: reply_envelope,
        },
    )
    .await;
    drain_send_responses(&mut br1).await;

    // ── Alice receives and decrypts Bob's reply ──
    let resp = recv(&mut ar2).await;
    let ServerMessage::IncomingMessage(reply_inbound) = resp else {
        panic!("expected IncomingMessage: {resp:?}");
    };
    assert_eq!(reply_inbound.sender_id.as_str(), "bob");
    assert_eq!(reply_inbound.message_id, reply_msg_id);

    let MessageHeader::Ratchet(ref reply_rh) = reply_inbound.envelope.header else {
        panic!("expected Ratchet header for reply");
    };

    let reply_crypto_header = crypto::ratchet::RatchetHeader {
        ratchet_key: b64_decode_fixed::<32>(&reply_rh.ratchet_key),
        previous_chain_length: reply_rh.previous_chain_length,
        message_number: reply_rh.message_number,
    };
    let reply_ciphertext = B64.decode(&reply_inbound.envelope.ciphertext).unwrap();
    let alice_decrypted =
        ratchet::decrypt(&mut alice_state, &reply_crypto_header, &reply_ciphertext).unwrap();
    assert_eq!(
        alice_decrypted, bob_plaintext,
        "Bob → Alice decryption failed"
    );
}

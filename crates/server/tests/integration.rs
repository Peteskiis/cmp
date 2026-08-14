#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

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

/// Send a `ClientMessage` as JSON.
async fn send(sink: &mut WsSink, msg: &ClientMessage) {
    let json = serde_json::to_string(msg).unwrap();
    sink.send(Message::Text(json.into())).await.unwrap();
}

/// Receive and parse a `ServerMessage`.
async fn recv(stream: &mut WsStream) -> ServerMessage {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text).unwrap();
            }
            Some(Ok(Message::Ping(_))) => {}
            other => panic!("unexpected message: {other:?}"),
        }
    }
}

fn make_identity() -> crypto::keys::IdentityKeyPair {
    crypto::keys::IdentityKeyPair::generate()
}

fn make_bundle(identity: &crypto::keys::IdentityKeyPair) -> (PreKeyBundle, Vec<OneTimePreKey>) {
    let signed_prekey = crypto::keys::SignedPreKey::generate(0, identity);
    let one_time_prekeys = crypto::keys::generate_one_time_prekeys(0, 20).unwrap();
    let bundle = PreKeyBundle {
        identity_key: B64.encode(identity.verifying_key().as_bytes()),
        signed_prekey: B64.encode(signed_prekey.public().as_bytes()),
        signed_prekey_id: signed_prekey.key_id(),
        signed_prekey_signature: B64.encode(signed_prekey.signature().to_bytes()),
        one_time_prekey: None,
    };
    let public_prekeys = one_time_prekeys
        .iter()
        .map(|prekey| OneTimePreKey {
            key_id: prekey.key_id(),
            public_key: B64.encode(prekey.public().as_bytes()),
        })
        .collect();
    (bundle, public_prekeys)
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
        version: protocol::consts::PROTOCOL_VERSION,
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
    let ack_id = MessageId::new();
    send(
        &mut bs2,
        &ClientMessage::Ack {
            ack_id: ack_id.clone(),
            message_ids: ids.clone(),
        },
    )
    .await;
    assert!(matches!(
        recv(&mut br2).await,
        ServerMessage::AckSuccess { ack_id: confirmed, message_ids }
            if confirmed == ack_id && message_ids == ids
    ));
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
async fn malformed_envelope_keys_are_rejected_on_all_relay_paths() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();
    let (mut alice_sink, mut alice_stream) = connect(&url).await;
    register(&mut alice_sink, &mut alice_stream, "alice", &alice_id).await;
    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    register(&mut bob_sink, &mut bob_stream, "bob", &bob_id).await;

    let invalid = EncryptedEnvelope {
        version: protocol::consts::PROTOCOL_VERSION,
        header: MessageHeader::Ratchet(ProtoRatchetHeader {
            ratchet_key: B64.encode([0u8; 31]),
            previous_chain_length: 0,
            message_number: 0,
        }),
        ciphertext: B64.encode(b"opaque"),
    };
    send(
        &mut alice_sink,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("bob").unwrap(),
            message_id: MessageId::new(),
            envelope: invalid.clone(),
        },
    )
    .await;
    assert!(matches!(
        recv(&mut alice_stream).await,
        ServerMessage::Error { code: 400, .. }
    ));

    send(
        &mut alice_sink,
        &ClientMessage::SendReadReceipt {
            recipient_id: UserId::new("bob").unwrap(),
            receipt_id: MessageId::new(),
            envelope: invalid,
        },
    )
    .await;
    assert!(matches!(
        recv(&mut alice_stream).await,
        ServerMessage::Error { code: 400, .. }
    ));
    drop((bob_sink, bob_stream));
}

#[tokio::test]
async fn unsupported_envelope_versions_are_rejected_on_all_relay_paths() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();
    let (mut alice_sink, mut alice_stream) = connect(&url).await;
    register(&mut alice_sink, &mut alice_stream, "alice", &alice_id).await;
    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    register(&mut bob_sink, &mut bob_stream, "bob", &bob_id).await;

    for unsupported_version in [
        protocol::consts::PROTOCOL_VERSION - 1,
        protocol::consts::PROTOCOL_VERSION + 1,
    ] {
        let mut unsupported = dummy_envelope("opaque");
        unsupported.version = unsupported_version;
        send(
            &mut alice_sink,
            &ClientMessage::SendMessage {
                recipient_id: UserId::new("bob").unwrap(),
                message_id: MessageId::new(),
                envelope: unsupported.clone(),
            },
        )
        .await;
        assert!(matches!(
            recv(&mut alice_stream).await,
            ServerMessage::Error { code: 400, .. }
        ));

        send(
            &mut alice_sink,
            &ClientMessage::SendReadReceipt {
                recipient_id: UserId::new("bob").unwrap(),
                receipt_id: MessageId::new(),
                envelope: unsupported,
            },
        )
        .await;
        assert!(matches!(
            recv(&mut alice_stream).await,
            ServerMessage::Error { code: 400, .. }
        ));
    }

    drop((bob_sink, bob_stream));
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
    let receipt_id = MessageId::new();
    send(
        &mut bs1,
        &ClientMessage::SendReadReceipt {
            recipient_id: UserId::new("alice").unwrap(),
            receipt_id: receipt_id.clone(),
            envelope: dummy_envelope("read-receipt-data"),
        },
    )
    .await;

    let resp = recv(&mut ar1).await;
    let ServerMessage::IncomingReadReceipt {
        sender_id,
        receipt_id: incoming_id,
        ..
    } = resp
    else {
        panic!("expected IncomingReadReceipt: {resp:?}");
    };
    assert_eq!(sender_id.as_str(), "bob");
    assert_eq!(incoming_id, receipt_id);

    let ack_id = MessageId::new();
    send(
        &mut as1,
        &ClientMessage::AckReadReceipt {
            ack_id: ack_id.clone(),
            receipt_ids: vec![receipt_id.clone()],
        },
    )
    .await;
    assert!(matches!(
        recv(&mut ar1).await,
        ServerMessage::AckSuccess { ack_id: confirmed, .. } if confirmed == ack_id
    ));
    assert!(matches!(
        recv(&mut br1).await,
        ServerMessage::ReadReceiptSent { receipt_id: sent } if sent == receipt_id
    ));
}

#[tokio::test]
async fn offline_read_receipt_is_queued_until_recipient_acknowledges() {
    let (url, _handle) = start_test_server().await;
    let alice_id = make_identity();
    let bob_id = make_identity();
    let (mut alice_sink, mut alice_stream) = connect(&url).await;
    register(&mut alice_sink, &mut alice_stream, "alice", &alice_id).await;
    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    register(&mut bob_sink, &mut bob_stream, "bob", &bob_id).await;
    drop((alice_sink, alice_stream));

    let receipt_id = MessageId::new();
    send(
        &mut bob_sink,
        &ClientMessage::SendReadReceipt {
            recipient_id: UserId::new("alice").unwrap(),
            receipt_id: receipt_id.clone(),
            envelope: dummy_envelope("retry me"),
        },
    )
    .await;

    let (mut alice_sink, mut alice_stream) = connect(&url).await;
    auth_challenge_response(&mut alice_sink, &mut alice_stream, "alice", &alice_id).await;
    assert!(matches!(
        recv(&mut alice_stream).await,
        ServerMessage::IncomingReadReceipt { receipt_id: incoming, .. } if incoming == receipt_id
    ));
    drop((bob_sink, bob_stream));
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let ack_id = MessageId::new();
    send(
        &mut alice_sink,
        &ClientMessage::AckReadReceipt {
            ack_id: ack_id.clone(),
            receipt_ids: vec![receipt_id.clone()],
        },
    )
    .await;
    assert!(matches!(
        recv(&mut alice_stream).await,
        ServerMessage::AckSuccess { ack_id: confirmed, .. } if confirmed == ack_id
    ));

    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    auth_challenge_response(&mut bob_sink, &mut bob_stream, "bob", &bob_id).await;
    assert!(matches!(
        recv(&mut bob_stream).await,
        ServerMessage::ReadReceiptSent { receipt_id: sent } if sent == receipt_id
    ));
    send(
        &mut bob_sink,
        &ClientMessage::AckReadReceiptSent {
            receipt_ids: vec![receipt_id],
        },
    )
    .await;
    assert!(matches!(
        recv(&mut bob_stream).await,
        ServerMessage::Success
    ));
}

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::Signer;
use futures::{SinkExt, StreamExt};
use protocol::{ClientMessage, MessageId, OneTimePreKey, PreKeyBundle, ServerMessage, UserId};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};

type WebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = futures::stream::SplitSink<WebSocket, Message>;
type WsStream = futures::stream::SplitStream<WebSocket>;

async fn start_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let handle = server::start_server(listener, "test-server").await.unwrap();
    (url, handle)
}

async fn connect(url: &str) -> (WsSink, WsStream) {
    connect_async(url).await.unwrap().0.split()
}

async fn send(sink: &mut WsSink, message: &ClientMessage) {
    let json = serde_json::to_string(message).unwrap();
    sink.send(Message::Text(json.into())).await.unwrap();
}

async fn recv(stream: &mut WsStream) -> ServerMessage {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
            Some(Ok(Message::Ping(_))) => {}
            other => panic!("unexpected message: {other:?}"),
        }
    }
}

async fn register(sink: &mut WsSink, stream: &mut WsStream, user: &str) {
    let _ = register_identity(sink, stream, user).await;
}

async fn register_identity(
    sink: &mut WsSink,
    stream: &mut WsStream,
    user: &str,
) -> crypto::keys::IdentityKeyPair {
    let identity = crypto::keys::IdentityKeyPair::generate();
    let signed_prekey = crypto::keys::SignedPreKey::generate(0, &identity);
    let private_prekeys = crypto::keys::generate_one_time_prekeys(0, 5).unwrap();
    let one_time_prekeys = private_prekeys
        .iter()
        .map(|prekey| OneTimePreKey {
            key_id: prekey.key_id(),
            public_key: B64.encode(prekey.public().as_bytes()),
        })
        .collect();
    let bundle = PreKeyBundle {
        identity_key: B64.encode(identity.verifying_key().as_bytes()),
        signed_prekey: B64.encode(signed_prekey.public().as_bytes()),
        signed_prekey_id: signed_prekey.key_id(),
        signed_prekey_signature: B64.encode(signed_prekey.signature().to_bytes()),
        one_time_prekey: None,
    };
    send(
        sink,
        &ClientMessage::Register {
            user_id: UserId::new(user).unwrap(),
            bundle,
            one_time_prekeys,
        },
    )
    .await;
    assert!(matches!(recv(stream).await, ServerMessage::AuthSuccess));
    identity
}

async fn authenticate(
    sink: &mut WsSink,
    stream: &mut WsStream,
    user: &str,
    identity: &crypto::keys::IdentityKeyPair,
) {
    send(
        sink,
        &ClientMessage::AuthChallenge {
            user_id: UserId::new(user).unwrap(),
        },
    )
    .await;
    let ServerMessage::Challenge {
        nonce,
        timestamp,
        server_id,
    } = recv(stream).await
    else {
        panic!("expected challenge");
    };
    let mut signed_data = B64.decode(nonce).unwrap();
    signed_data.extend_from_slice(&timestamp.to_be_bytes());
    signed_data.extend_from_slice(server_id.as_bytes());
    send(
        sink,
        &ClientMessage::AuthResponse {
            signature: B64.encode(identity.signing_key().sign(&signed_data).to_bytes()),
        },
    )
    .await;
    assert!(matches!(recv(stream).await, ServerMessage::AuthSuccess));
}

#[tokio::test]
async fn prekey_bundle_self_fetch_is_rejected() {
    let (url, _handle) = start_test_server().await;
    let (mut sink, mut stream) = connect(&url).await;
    register(&mut sink, &mut stream, "alice").await;

    send(
        &mut sink,
        &ClientMessage::FetchPreKeyBundle {
            target_user_id: UserId::new("alice").unwrap(),
        },
    )
    .await;
    assert!(matches!(
        recv(&mut stream).await,
        ServerMessage::Error { code: 400, .. }
    ));
}

#[tokio::test]
async fn authentication_reports_low_prekey_inventory() {
    let (url, _handle) = start_test_server().await;
    let (mut sink, mut stream) = connect(&url).await;
    let identity = register_identity(&mut sink, &mut stream, "alice").await;
    drop((sink, stream));

    let (mut sink, mut stream) = connect(&url).await;
    authenticate(&mut sink, &mut stream, "alice", &identity).await;
    assert!(matches!(
        recv(&mut stream).await,
        ServerMessage::PreKeyLow { remaining: 5 }
    ));
}

#[tokio::test]
async fn prekey_upload_is_correlated_capped_and_idempotent() {
    let (url, _handle) = start_test_server().await;
    let (mut sink, mut stream) = connect(&url).await;
    register(&mut sink, &mut stream, "alice").await;

    let make_prekeys = |count: u32| {
        ((1 << 31)..(1 << 31) + count)
            .map(|key_id| OneTimePreKey {
                key_id,
                public_key: B64.encode([7_u8; 32]),
            })
            .collect::<Vec<_>>()
    };
    let rejected_id = MessageId::new();
    send(
        &mut sink,
        &ClientMessage::UploadPreKeys {
            upload_id: rejected_id.clone(),
            prekeys: make_prekeys(196),
        },
    )
    .await;
    assert!(matches!(
        recv(&mut stream).await,
        ServerMessage::PreKeysUploaded {
            upload_id,
            accepted: false,
            remaining: 5,
        } if upload_id == rejected_id
    ));

    let accepted_id = MessageId::new();
    let accepted_prekeys = make_prekeys(195);
    for _ in 0..2 {
        send(
            &mut sink,
            &ClientMessage::UploadPreKeys {
                upload_id: accepted_id.clone(),
                prekeys: accepted_prekeys.clone(),
            },
        )
        .await;
        assert!(matches!(
            recv(&mut stream).await,
            ServerMessage::PreKeysUploaded {
                upload_id,
                accepted: true,
                remaining: 200,
            } if upload_id == accepted_id
        ));
    }

    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    register(&mut bob_sink, &mut bob_stream, "bob").await;
    send(
        &mut bob_sink,
        &ClientMessage::FetchPreKeyBundle {
            target_user_id: UserId::new("alice").unwrap(),
        },
    )
    .await;
    assert!(matches!(
        recv(&mut bob_stream).await,
        ServerMessage::PreKeyBundleResponse { .. }
    ));
    send(
        &mut sink,
        &ClientMessage::UploadPreKeys {
            upload_id: accepted_id.clone(),
            prekeys: accepted_prekeys,
        },
    )
    .await;
    assert!(matches!(
        recv(&mut stream).await,
        ServerMessage::PreKeysUploaded {
            upload_id,
            accepted: true,
            remaining: 199,
        } if upload_id == accepted_id
    ));
}

#[tokio::test]
async fn signed_prekey_rotation_is_authenticated_idempotent_and_published() {
    let (url, _handle) = start_test_server().await;
    let (mut alice_sink, mut alice_stream) = connect(&url).await;
    let alice_identity = register_identity(&mut alice_sink, &mut alice_stream, "alice").await;
    let signed_prekey = crypto::keys::SignedPreKey::generate(1, &alice_identity);
    let rotation_id = MessageId::new();
    let rotation = ClientMessage::RotateSignedPreKey {
        rotation_id: rotation_id.clone(),
        key_id: signed_prekey.key_id(),
        public_key: B64.encode(signed_prekey.public().as_bytes()),
        signature: B64.encode(signed_prekey.signature().to_bytes()),
    };
    for _ in 0..2 {
        send(&mut alice_sink, &rotation).await;
        assert!(matches!(
            recv(&mut alice_stream).await,
            ServerMessage::SignedPreKeyRotated {
                rotation_id: response_id,
                accepted: true,
            } if response_id == rotation_id
        ));
    }

    send(
        &mut alice_sink,
        &ClientMessage::RotateSignedPreKey {
            rotation_id: MessageId::new(),
            key_id: 2,
            public_key: B64.encode([9_u8; 32]),
            signature: B64.encode([0_u8; 64]),
        },
    )
    .await;
    assert!(matches!(
        recv(&mut alice_stream).await,
        ServerMessage::Error { code: 400, .. }
    ));

    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    register(&mut bob_sink, &mut bob_stream, "bob").await;
    send(
        &mut bob_sink,
        &ClientMessage::FetchPreKeyBundle {
            target_user_id: UserId::new("alice").unwrap(),
        },
    )
    .await;
    assert!(matches!(
        recv(&mut bob_stream).await,
        ServerMessage::PreKeyBundleResponse { bundle, .. }
            if bundle.signed_prekey_id == 1
                && bundle.signed_prekey == B64.encode(signed_prekey.public().as_bytes())
    ));
}

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use base64::{Engine, engine::general_purpose::STANDARD as B64};
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
async fn prekey_upload_is_correlated_capped_and_idempotent() {
    let (url, _handle) = start_test_server().await;
    let (mut sink, mut stream) = connect(&url).await;
    register(&mut sink, &mut stream, "alice").await;

    let make_prekeys = |count: u32| {
        (1_000..1_000 + count)
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
}

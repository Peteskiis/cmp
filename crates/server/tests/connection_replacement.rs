#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::Signer;
use futures::{SinkExt, StreamExt};
use protocol::{ClientMessage, OneTimePreKey, PreKeyBundle, ServerMessage, UserId};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};

type WsStream = futures::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;
type WsSink = futures::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>;

async fn start_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = server::start_server(listener, "test-server").await.unwrap();
    (format!("ws://{address}/ws"), handle)
}

async fn connect(url: &str) -> (WsSink, WsStream) {
    let (socket, _) = connect_async(url).await.unwrap();
    socket.split()
}

async fn send(sink: &mut WsSink, message: &ClientMessage) {
    let encoded = serde_json::to_string(message).unwrap();
    sink.send(Message::Text(encoded.into())).await.unwrap();
}

async fn recv(stream: &mut WsStream) -> ServerMessage {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
            Some(Ok(Message::Ping(_))) => {}
            message => panic!("unexpected message: {message:?}"),
        }
    }
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
    let (bundle, one_time_prekeys) = make_bundle(identity);
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
    let signature = identity.signing_key().sign(&signed_data);
    send(
        sink,
        &ClientMessage::AuthResponse {
            signature: B64.encode(signature.to_bytes()),
        },
    )
    .await;
    assert!(matches!(recv(stream).await, ServerMessage::AuthSuccess));
}

#[tokio::test]
async fn replacement_stops_old_session_and_preserves_new_delivery() {
    let (url, _handle) = start_test_server().await;
    let alice_identity = crypto::keys::IdentityKeyPair::generate();
    let bob_identity = crypto::keys::IdentityKeyPair::generate();

    let (mut old_alice_sink, mut old_alice_stream) = connect(&url).await;
    register(
        &mut old_alice_sink,
        &mut old_alice_stream,
        "alice",
        &alice_identity,
    )
    .await;
    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    register(&mut bob_sink, &mut bob_stream, "bob", &bob_identity).await;

    let (mut new_alice_sink, mut new_alice_stream) = connect(&url).await;
    authenticate(
        &mut new_alice_sink,
        &mut new_alice_stream,
        "alice",
        &alice_identity,
    )
    .await;
    assert!(matches!(
        recv(&mut old_alice_stream).await,
        ServerMessage::Error { code: 409, .. }
    ));

    let stale_message = ClientMessage::Typing {
        recipient_id: UserId::new("bob").unwrap(),
    };
    let stale_json = serde_json::to_string(&stale_message).unwrap();
    if old_alice_sink
        .send(Message::Text(stale_json.into()))
        .await
        .is_ok()
    {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), recv(&mut bob_stream))
                .await
                .is_err(),
            "displaced connection relayed a message"
        );
    }

    send(
        &mut bob_sink,
        &ClientMessage::Typing {
            recipient_id: UserId::new("alice").unwrap(),
        },
    )
    .await;
    loop {
        match recv(&mut new_alice_stream).await {
            ServerMessage::PeerTyping { sender_id } => {
                assert_eq!(sender_id.as_str(), "bob");
                break;
            }
            ServerMessage::PreKeyLow { .. } => {}
            message => panic!("unexpected replacement response: {message:?}"),
        }
    }
}

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::Signer;
use futures::{SinkExt, StreamExt};
use protocol::{
    ClientMessage, EncryptedEnvelope, MessageId, ServerMessage, UserId, consts,
    types::{MessageHeader, PreKeyBundle, RatchetHeader},
};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = futures::stream::SplitSink<Ws, Message>;
type WsStream = futures::stream::SplitStream<Ws>;

async fn start_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = server::start_server(listener, "test-server").await.unwrap();
    (format!("ws://{address}/ws"), handle)
}

async fn connect(url: &str) -> (WsSink, WsStream) {
    connect_async(url).await.unwrap().0.split()
}

async fn send(sink: &mut WsSink, message: &ClientMessage) {
    let encoded = serde_json::to_string(message).unwrap();
    sink.send(Message::Text(encoded.into())).await.unwrap();
}

async fn receive(stream: &mut WsStream) -> (ServerMessage, usize) {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => {
                let encoded_len = text.len();
                return (serde_json::from_str(&text).unwrap(), encoded_len);
            }
            Some(Ok(Message::Ping(_))) => {}
            other => panic!("unexpected WebSocket message: {other:?}"),
        }
    }
}

fn bundle(identity: &crypto::keys::IdentityKeyPair) -> PreKeyBundle {
    let signed_prekey = crypto::keys::SignedPreKey::generate(0, identity);
    PreKeyBundle {
        identity_key: B64.encode(identity.verifying_key().as_bytes()),
        signed_prekey: B64.encode(signed_prekey.public().as_bytes()),
        signed_prekey_id: signed_prekey.key_id(),
        signed_prekey_signature: B64.encode(signed_prekey.signature().to_bytes()),
        one_time_prekey: None,
    }
}

async fn register(
    sink: &mut WsSink,
    stream: &mut WsStream,
    user_id: &str,
    identity: &crypto::keys::IdentityKeyPair,
) {
    send(
        sink,
        &ClientMessage::Register {
            user_id: UserId::new(user_id).unwrap(),
            bundle: bundle(identity),
            one_time_prekeys: Vec::new(),
        },
    )
    .await;
    assert!(matches!(
        receive(stream).await.0,
        ServerMessage::AuthSuccess
    ));
}

async fn authenticate(
    sink: &mut WsSink,
    stream: &mut WsStream,
    user_id: &str,
    identity: &crypto::keys::IdentityKeyPair,
) {
    send(
        sink,
        &ClientMessage::AuthChallenge {
            user_id: UserId::new(user_id).unwrap(),
        },
    )
    .await;
    let ServerMessage::Challenge {
        nonce,
        timestamp,
        server_id,
    } = receive(stream).await.0
    else {
        panic!("expected authentication challenge");
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
    assert!(matches!(
        receive(stream).await.0,
        ServerMessage::AuthSuccess
    ));
}

fn envelope(ciphertext: String) -> EncryptedEnvelope {
    EncryptedEnvelope {
        version: protocol::consts::PROTOCOL_VERSION,
        header: MessageHeader::Ratchet(RatchetHeader {
            ratchet_key: B64.encode([0; 32]),
            previous_chain_length: 0,
            message_number: 0,
        }),
        ciphertext,
    }
}

async fn queue_for_bob(
    alice_sink: &mut WsSink,
    alice_stream: &mut WsStream,
    envelope: EncryptedEnvelope,
) {
    let message_id = MessageId::new();
    send(
        alice_sink,
        &ClientMessage::SendMessage {
            recipient_id: UserId::new("bob").unwrap(),
            message_id: message_id.clone(),
            envelope,
        },
    )
    .await;
    assert!(matches!(
        receive(alice_stream).await.0,
        ServerMessage::MessageSent { message_id: sent } if sent == message_id
    ));
}

async fn setup() -> (String, crypto::keys::IdentityKeyPair, WsSink, WsStream) {
    let (url, _server) = start_test_server().await;
    let alice_identity = crypto::keys::IdentityKeyPair::generate();
    let bob_identity = crypto::keys::IdentityKeyPair::generate();

    let (mut alice_sink, mut alice_stream) = connect(&url).await;
    register(&mut alice_sink, &mut alice_stream, "alice", &alice_identity).await;

    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    register(&mut bob_sink, &mut bob_stream, "bob", &bob_identity).await;
    drop((bob_sink, bob_stream));
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    (url, bob_identity, alice_sink, alice_stream)
}

#[tokio::test]
async fn queued_delivery_pages_by_message_count() {
    let (url, bob_identity, mut alice_sink, mut alice_stream) = setup().await;
    for index in 0..=consts::MAX_QUEUED_MESSAGES_PER_PAGE {
        queue_for_bob(
            &mut alice_sink,
            &mut alice_stream,
            envelope(B64.encode(format!("message {index}"))),
        )
        .await;
    }

    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    authenticate(&mut bob_sink, &mut bob_stream, "bob", &bob_identity).await;

    let mut page_lengths = Vec::new();
    for _ in 0..2 {
        let (ServerMessage::QueuedMessages { messages }, encoded_len) =
            receive(&mut bob_stream).await
        else {
            panic!("expected queued message page");
        };
        assert!(encoded_len <= consts::MAX_QUEUED_PAGE_BYTES);
        page_lengths.push(messages.len());
    }
    assert_eq!(page_lengths, [consts::MAX_QUEUED_MESSAGES_PER_PAGE, 1]);
}

#[tokio::test]
async fn queued_delivery_pages_by_encoded_bytes() {
    let (url, bob_identity, mut alice_sink, mut alice_stream) = setup().await;
    queue_for_bob(
        &mut alice_sink,
        &mut alice_stream,
        envelope("A".repeat(consts::MAX_CIPHERTEXT_BYTES)),
    )
    .await;
    queue_for_bob(
        &mut alice_sink,
        &mut alice_stream,
        envelope("A".repeat(32 * 1024)),
    )
    .await;

    let (mut bob_sink, mut bob_stream) = connect(&url).await;
    authenticate(&mut bob_sink, &mut bob_stream, "bob", &bob_identity).await;

    for _ in 0..2 {
        let (ServerMessage::QueuedMessages { messages }, encoded_len) =
            receive(&mut bob_stream).await
        else {
            panic!("expected queued message page");
        };
        assert_eq!(messages.len(), 1);
        assert!(encoded_len <= consts::MAX_QUEUED_PAGE_BYTES);
    }
}

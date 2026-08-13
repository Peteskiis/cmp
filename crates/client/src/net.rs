use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::Signer;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use protocol::{ClientMessage, OneTimePreKey, PreKeyBundle, ServerMessage, UserId};
use tokio::sync::mpsc;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

use crate::crypto_mgr::CryptoManager;
use tracing::{info, warn};

use crate::app::AppEvent;

/// Connect to the server, authenticate, and relay messages.
/// `validated_uid` must be pre-validated at startup.
#[allow(clippy::cognitive_complexity)]
pub(crate) async fn run(
    server_url: String,
    validated_uid: UserId,
    identity: &crypto::keys::IdentityKeyPair,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    mut outgoing_rx: mpsc::UnboundedReceiver<ClientMessage>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    loop {
        info!("connecting to {server_url}");
        let _ = event_tx.send(AppEvent::Connecting);

        let Ok((ws, _)) = connect_async(&server_url).await else {
            let _ = event_tx.send(AppEvent::Disconnected);
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
            continue;
        };
        // Don't reset backoff here — only after successful auth

        let (mut sink, mut stream) = ws.split();
        let _ = event_tx.send(AppEvent::Connected);

        // Send AuthChallenge
        let Ok(json) = serde_json::to_string(&ClientMessage::AuthChallenge {
            user_id: validated_uid.clone(),
        }) else {
            let _ = event_tx.send(AppEvent::AuthFailed("internal serialization error".into()));
            return;
        };
        if sink.send(Message::Text(json.into())).await.is_err() {
            let _ = event_tx.send(AppEvent::Disconnected);
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }

        // Handle challenge-response
        let auth_ok = match stream.next().await {
            Some(Ok(Message::Text(text))) => handle_auth_flow(&text, identity, &mut sink).await,
            _ => false,
        };
        if !auth_ok {
            warn!("authentication failed — challenge-response");
            let _ = event_tx.send(AppEvent::AuthFailed("challenge-response failed".into()));
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }

        // Wait for AuthSuccess
        let got_success = matches!(
            stream.next().await,
            Some(Ok(Message::Text(ref t))) if matches!(serde_json::from_str::<ServerMessage>(t), Ok(ServerMessage::AuthSuccess))
        );
        if !got_success {
            warn!("did not receive AuthSuccess");
            let _ = event_tx.send(AppEvent::AuthFailed(
                "server rejected authentication".into(),
            ));
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }

        // Auth succeeded — reset backoff
        backoff = Duration::from_secs(1);
        // Drop the stale transport backlog before the app replays its ordered
        // durable outbox. Messages and receipts are persisted before entering
        // this channel; ephemeral commands are intentionally not replayed.
        drain_stale_outgoing(&mut outgoing_rx);
        let _ = event_tx.send(AppEvent::Authenticated);

        relay_loop(&mut stream, &mut sink, &event_tx, &mut outgoing_rx).await;

        let _ = event_tx.send(AppEvent::Disconnected);
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
}

fn drain_stale_outgoing(outgoing_rx: &mut mpsc::UnboundedReceiver<ClientMessage>) {
    while outgoing_rx.try_recv().is_ok() {}
}

type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>;
type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, Message>;

#[allow(clippy::cognitive_complexity)]
async fn relay_loop(
    stream: &mut WsStream,
    sink: &mut WsSink,
    event_tx: &mpsc::UnboundedSender<AppEvent>,
    outgoing_rx: &mut mpsc::UnboundedReceiver<ClientMessage>,
) {
    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ServerMessage>(&text) {
                            Ok(server_msg) => { let _ = event_tx.send(AppEvent::Server(server_msg)); }
                            Err(e) => { warn!("unparseable server message: {e}"); }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            Some(client_msg) = outgoing_rx.recv() => {
                if let Ok(json) = serde_json::to_string(&client_msg)
                    && sink.send(Message::Text(json.into())).await.is_err()
                {
                    break;
                }
            }
        }
    }
}

async fn handle_auth_flow(
    text: &str,
    identity: &crypto::keys::IdentityKeyPair,
    sink: &mut WsSink,
) -> bool {
    let Ok(ServerMessage::Challenge {
        nonce,
        timestamp,
        server_id,
    }) = serde_json::from_str(text)
    else {
        return false;
    };

    let Ok(nonce_bytes) = B64.decode(&nonce) else {
        return false;
    };

    let mut signed_data = Vec::with_capacity(nonce_bytes.len() + 8 + server_id.len());
    signed_data.extend_from_slice(&nonce_bytes);
    signed_data.extend_from_slice(&timestamp.to_be_bytes());
    signed_data.extend_from_slice(server_id.as_bytes());

    let signature = identity.signing_key().sign(&signed_data);
    let response = ClientMessage::AuthResponse {
        signature: B64.encode(signature.to_bytes()),
    };
    let Ok(json) = serde_json::to_string(&response) else {
        return false;
    };

    sink.send(Message::Text(json.into())).await.is_ok()
}

/// One-shot registration: connect, upload bundle, wait for confirmation.
pub(crate) async fn register_with_server(
    user_id: &str,
    server_url: &str,
    crypto: &mut CryptoManager,
) -> anyhow::Result<()> {
    let identity = crypto.identity();
    let (ws, _) = connect_async(server_url).await?;
    let (mut sink, mut stream) = ws.split();

    let spk = crypto::keys::SignedPreKey::generate(0, identity);
    let prekey_count = u32::try_from(protocol::consts::PREKEY_TARGET)?;
    let opks = crypto::keys::generate_one_time_prekeys(0, prekey_count)?;

    let bundle = PreKeyBundle {
        identity_key: B64.encode(identity.verifying_key().as_bytes()),
        signed_prekey: B64.encode(spk.public().as_bytes()),
        signed_prekey_id: spk.key_id(),
        signed_prekey_signature: B64.encode(spk.signature().to_bytes()),
        one_time_prekey: None,
    };

    let otk_uploads: Vec<OneTimePreKey> = opks
        .iter()
        .map(|k| OneTimePreKey {
            key_id: k.key_id(),
            public_key: B64.encode(k.public().as_bytes()),
        })
        .collect();

    let uid = UserId::new(user_id)?;
    let register = ClientMessage::Register {
        user_id: uid,
        bundle,
        one_time_prekeys: otk_uploads,
    };

    let json = serde_json::to_string(&register)?;
    SinkExt::send(&mut sink, Message::Text(json.into())).await?;

    let Some(Ok(Message::Text(text))) = stream.next().await else {
        anyhow::bail!("no response from server during registration");
    };

    if matches!(serde_json::from_str(&text), Ok(ServerMessage::AuthSuccess)) {
        crypto.persist_registration_keys(&spk, &opks)?;
        return Ok(());
    }
    if let Ok(ServerMessage::AuthFailure { reason }) = serde_json::from_str(&text) {
        anyhow::bail!("registration rejected: {reason}");
    }
    anyhow::bail!("unexpected server response during registration");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_discards_stale_transport_backlog_before_durable_replay() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        sender
            .send(ClientMessage::Typing {
                recipient_id: UserId::new("bob").unwrap(),
            })
            .unwrap();
        sender
            .send(ClientMessage::Typing {
                recipient_id: UserId::new("carol").unwrap(),
            })
            .unwrap();

        drain_stale_outgoing(&mut receiver);
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}

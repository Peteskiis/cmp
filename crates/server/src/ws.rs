use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use protocol::{ClientMessage, ServerMessage};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::handlers;
use crate::handlers::Session;
use crate::state::AppState;

/// Max WebSocket message size: `MAX_CIPHERTEXT_BYTES` + 16 KB headroom for JSON envelope overhead.
const MAX_WS_MESSAGE_SIZE: usize = 512 * 1024 + 16 * 1024;

pub async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.max_frame_size(MAX_WS_MESSAGE_SIZE)
        .max_message_size(MAX_WS_MESSAGE_SIZE)
        .on_upgrade(move |socket| handle_connection(socket, state))
}

#[allow(clippy::cognitive_complexity)] // Inherent in connection lifecycle management.
async fn handle_connection(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();

    // Bounded channel — backpressure on slow/malicious clients.
    let (tx, mut rx) = mpsc::channel::<ServerMessage>(256);

    let write_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match serde_json::to_string(&msg) {
                Ok(json) => {
                    if sink.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => error!("failed to serialize ServerMessage: {e}"),
            }
        }
    });

    let mut session = Session::new();

    while let Some(Ok(msg)) = stream.next().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };

        let client_msg: ClientMessage = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("malformed client message: {e}");
                let _ = tx.try_send(ServerMessage::Error {
                    code: 400,
                    message: "malformed message".to_owned(),
                });
                continue;
            }
        };

        let was_authed = session.authed_user.is_some();

        let response = handlers::handle_message(&state, &tx, &mut session, client_msg).await;

        if let Some(msg) = response
            && tx.try_send(msg).is_err()
        {
            break;
        }

        // Deliver queued messages after AuthSuccess is on the wire
        if !was_authed && let Some(ref uid) = session.authed_user {
            handlers::auth::deliver_queued_messages(&state, &tx, uid).await;
        }
    }

    // Cleanup: only remove if our conn_id still matches (prevents race with replacement)
    if let (Some(user_id), Some(cid)) = (&session.authed_user, session.conn_id) {
        state.connections.remove_if_match(user_id, cid);
        info!(user_id, "disconnected");
    }

    write_task.abort();
}

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

/// Bounds queued server output for a slow client to roughly four MiB at the
/// maximum WebSocket page size, plus the frame currently being written.
const OUTBOUND_CHANNEL_CAPACITY: usize = 8;

pub(crate) async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.max_frame_size(protocol::consts::MAX_QUEUED_PAGE_BYTES)
        .max_message_size(protocol::consts::MAX_QUEUED_PAGE_BYTES)
        .on_upgrade(move |socket| handle_connection(socket, state))
}

#[allow(clippy::cognitive_complexity)] // Inherent in connection lifecycle management.
async fn handle_connection(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();

    // Bounded channel — backpressure on slow/malicious clients.
    let (tx, mut rx) = mpsc::channel::<ServerMessage>(OUTBOUND_CHANNEL_CAPACITY);

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
            handlers::auth::deliver_message_confirmations(&state, &tx, uid).await;
            handlers::auth::deliver_queued_receipts(&state, &tx, uid).await;
            if session.deliver_prekey_status {
                handlers::auth::deliver_prekey_status(&state, &tx, uid).await;
                session.deliver_prekey_status = false;
            }
        }
    }

    // Cleanup: only remove if our conn_id still matches (prevents race with replacement)
    if let (Some(user_id), Some(cid)) = (&session.authed_user, session.conn_id) {
        state.connections.remove_if_match(user_id, cid);
        info!(user_id, "disconnected");
    }

    write_task.abort();
}

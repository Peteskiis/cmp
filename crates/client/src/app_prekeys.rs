use protocol::{ClientMessage, UserId};
use tokio::sync::mpsc;

use super::App;

pub(super) fn refresh_expired_session(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    target: &UserId,
) -> bool {
    match app.crypto.expire_stale_prekey_session(target.as_str()) {
        Ok(true) => {
            app.crypto.add_pending(target.as_str());
            let _ = outgoing_tx.send(ClientMessage::FetchPreKeyBundle {
                target_user_id: target.clone(),
            });
            app.status("refreshing expired session keys...");
            true
        }
        Ok(false) => false,
        Err(error) => {
            app.status(&format!("session refresh failed: {error}"));
            true
        }
    }
}

pub(super) fn handle_message_rejected(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    message_id: &protocol::MessageId,
) {
    match app.crypto.reject_message(message_id) {
        Ok(Some(recipient_id)) => {
            app.crypto.add_pending(recipient_id.as_str());
            let _ = outgoing_tx.send(ClientMessage::FetchPreKeyBundle {
                target_user_id: recipient_id,
            });
        }
        Ok(None) => {}
        Err(error) => tracing::warn!("failed to retire rejected outbound message: {error}"),
    }
}

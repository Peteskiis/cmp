use protocol::{ClientMessage, UserId};
use tokio::sync::mpsc;

use super::App;

pub(super) fn queue_signed_prekey_rotation(app: &mut App) {
    if let Err(error) = app.crypto.queue_signed_prekey_rotation() {
        tracing::warn!("failed to queue signed prekey rotation: {error}");
    }
}

pub(super) fn handle_prekey_low(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    remaining: u32,
) {
    match app.crypto.queue_prekey_replenishment() {
        Ok(upload) => {
            let _ = outgoing_tx.send(upload);
            app.status(&format!(
                "replenishing one-time pre-keys ({remaining} remaining)"
            ));
        }
        Err(error) => app.status(&format!("pre-key replenishment failed: {error}")),
    }
}

pub(super) fn handle_prekeys_uploaded(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    upload_id: &protocol::MessageId,
    accepted: bool,
    remaining: u32,
) {
    match app
        .crypto
        .confirm_prekeys_uploaded(upload_id, accepted, remaining)
    {
        Ok(replacement) => {
            send_replacement(outgoing_tx, replacement);
            app.status(&prekey_upload_status(accepted, remaining));
        }
        Err(error) => tracing::warn!("failed to confirm durable pre-key upload: {error}"),
    }
}

fn send_replacement(
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    replacement: Option<ClientMessage>,
) {
    if let Some(upload) = replacement {
        let _ = outgoing_tx.send(upload);
    }
}

fn prekey_upload_status(accepted: bool, remaining: u32) -> String {
    let status = if accepted {
        "one-time pre-keys replenished"
    } else {
        "pre-key upload rejected"
    };
    format!("{status} ({remaining} available)")
}

pub(super) fn handle_signed_prekey_rotated(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    rotation_id: &protocol::MessageId,
    accepted: bool,
    current_key_id: u32,
) {
    match app
        .crypto
        .confirm_signed_prekey_rotated(rotation_id, accepted, current_key_id)
    {
        Ok(Some(replacement)) => {
            let _ = outgoing_tx.send(replacement);
            app.status("signed pre-key rotation reconciled; retrying");
        }
        Ok(None) if accepted => app.status("signed pre-key rotated"),
        Ok(None) => app.status("signed pre-key rotation rejected"),
        Err(error) => tracing::warn!("failed to confirm signed prekey rotation: {error}"),
    }
}

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

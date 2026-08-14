use protocol::{ClientMessage, UserId};
use tokio::sync::mpsc;

use super::App;

pub(super) fn queue_signed_prekey_rotation(app: &mut App) {
    if let Err(error) = app.crypto.queue_signed_prekey_rotation() {
        tracing::warn!("failed to queue signed prekey rotation: {error}");
    }
}

pub(super) fn handle_lifecycle_tick(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
) {
    if !app.authenticated {
        return;
    }
    queue_due_rotation(app, outgoing_tx);
}

fn queue_due_rotation(app: &mut App, outgoing_tx: &mpsc::UnboundedSender<ClientMessage>) {
    match app.crypto.queue_signed_prekey_rotation() {
        Ok(true) => send_pending_rotation(app, outgoing_tx),
        Ok(false) => {}
        Err(error) => tracing::warn!("failed to queue scheduled signed prekey rotation: {error}"),
    }
}

fn send_pending_rotation(app: &App, outgoing_tx: &mpsc::UnboundedSender<ClientMessage>) {
    if let Some(rotation) = app
        .crypto
        .pending_messages()
        .into_iter()
        .find(|message| matches!(message, ClientMessage::RotateSignedPreKey { .. }))
    {
        let _ = outgoing_tx.send(rotation);
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
    previously_accepted: bool,
    current_key_id: u32,
) {
    match app.crypto.confirm_signed_prekey_rotated(
        rotation_id,
        accepted,
        previously_accepted,
        current_key_id,
    ) {
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

#[cfg(test)]
mod tests {
    use crypto::keys::SignedPreKey;
    use tempfile::TempDir;

    use super::*;
    use crate::crypto_mgr::CryptoManager;

    #[test]
    fn lifecycle_tick_queues_and_sends_due_rotation_once() {
        let data_dir = TempDir::new().unwrap();
        let mut crypto = CryptoManager::load_or_generate(data_dir.path()).unwrap();
        let signed_prekey = SignedPreKey::generate(0, crypto.identity());
        crypto
            .persist_registration_keys(&signed_prekey, &[])
            .unwrap();
        crypto.force_signed_prekey_rotation_due();
        let mut app = App::new(UserId::new("alice").unwrap(), crypto, None);
        app.authenticated = true;
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();

        handle_lifecycle_tick(&mut app, &outgoing_tx);
        assert!(matches!(
            outgoing_rx.try_recv().unwrap(),
            ClientMessage::RotateSignedPreKey { key_id: 1, .. }
        ));
        handle_lifecycle_tick(&mut app, &outgoing_tx);
        assert!(outgoing_rx.try_recv().is_err());
    }
}

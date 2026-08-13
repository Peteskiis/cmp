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

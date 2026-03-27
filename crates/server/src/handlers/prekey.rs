use base64::{Engine, engine::general_purpose::STANDARD as B64};
use protocol::{OneTimePreKey, PreKeyBundle, ServerMessage, UserId, consts};

use super::{decode_prekeys, error_400, error_404, error_500_generic};
use crate::db;
use crate::state::AppState;

const PREKEY_LOW_THRESHOLD: u32 = 10;

#[allow(clippy::cognitive_complexity)]
pub async fn handle_fetch(state: &AppState, target_user_id: UserId) -> ServerMessage {
    let uid = target_user_id.as_str();

    let identity_key = match db::users::get_identity_key(&state.db, uid).await {
        Ok(Some(k)) => B64.encode(k),
        Ok(None) => return error_404(&format!("user not found: {uid}")),
        Err(e) => {
            return {
                tracing::error!("db error: {e}");
                error_500_generic()
            };
        }
    };

    let (spk_id, spk_bytes, sig_bytes) = match db::prekeys::get_signed_prekey(&state.db, uid).await
    {
        Ok(Some(spk)) => spk,
        Ok(None) => return error_404(&format!("no signed prekey for user: {uid}")),
        Err(e) => {
            return {
                tracing::error!("db error: {e}");
                error_500_generic()
            };
        }
    };

    let one_time_prekey = match db::prekeys::fetch_and_delete_prekey(&state.db, uid).await {
        Ok(Some((key_id, pk_bytes))) => Some(protocol::OneTimePreKey {
            key_id,
            public_key: B64.encode(pk_bytes),
        }),
        Ok(None) => None,
        Err(e) => {
            return {
                tracing::error!("db error: {e}");
                error_500_generic()
            };
        }
    };

    let bundle = PreKeyBundle {
        identity_key,
        signed_prekey: B64.encode(spk_bytes),
        signed_prekey_id: spk_id,
        signed_prekey_signature: B64.encode(sig_bytes),
        one_time_prekey,
    };

    if let Ok(remaining) = db::prekeys::count_prekeys(&state.db, uid).await
        && remaining < PREKEY_LOW_THRESHOLD
    {
        state
            .connections
            .send_to(uid, ServerMessage::PreKeyLow { remaining });
    }

    ServerMessage::PreKeyBundleResponse {
        user_id: target_user_id,
        bundle,
    }
}

#[allow(clippy::cognitive_complexity)]
pub async fn handle_upload(
    state: &AppState,
    user_id: &str,
    prekeys: Vec<OneTimePreKey>,
) -> ServerMessage {
    if prekeys.len() > consts::MAX_PREKEYS_PER_UPLOAD {
        return error_400("too many prekeys");
    }

    let pairs = match decode_prekeys(&prekeys) {
        Ok(p) => p,
        Err(msg) => return msg,
    };

    match db::prekeys::upload_prekeys(&state.db, user_id, &pairs).await {
        Ok(()) => ServerMessage::Success,
        Err(e) => {
            tracing::error!("failed to store prekeys: {e}");
            error_500_generic()
        }
    }
}

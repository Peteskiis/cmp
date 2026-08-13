use base64::{Engine, engine::general_purpose::STANDARD as B64};
use protocol::{MessageId, OneTimePreKey, PreKeyBundle, ServerMessage, UserId, consts};

use super::{decode_prekeys, error_400, error_404, error_429, error_500_generic, now_secs};
use crate::db;
use crate::state::AppState;

pub(super) const PREKEY_LOW_THRESHOLD: u32 = 10;
const FETCH_WINDOW_SECS: u64 = 60 * 60;
const FETCHES_PER_REQUESTER: u32 = 10;
const FETCHES_PER_TARGET: u32 = 20;

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn handle_fetch(
    state: &AppState,
    requester_id: &str,
    target_user_id: UserId,
) -> ServerMessage {
    let uid = target_user_id.as_str();
    if requester_id == uid {
        return error_400("cannot fetch your own pre-key bundle");
    }

    let identity_key = match db::users::get_identity_key(&state.db, uid).await {
        Ok(Some(k)) => B64.encode(k),
        Ok(None) => return error_404("not found"),
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
        Ok(None) => return error_404("not found"),
        Err(e) => {
            return {
                tracing::error!("db error: {e}");
                error_500_generic()
            };
        }
    };

    let one_time_prekey = match db::prekeys::fetch_for_requester(
        &state.db,
        requester_id,
        uid,
        now_secs(),
        db::prekeys::FetchLimits {
            window_secs: FETCH_WINDOW_SECS,
            per_requester: FETCHES_PER_REQUESTER,
            per_target: FETCHES_PER_TARGET,
        },
    )
    .await
    {
        Ok(db::prekeys::FetchResult::Fetched { key_id, public_key }) => {
            Some(protocol::OneTimePreKey {
                key_id,
                public_key: B64.encode(public_key),
            })
        }
        Ok(db::prekeys::FetchResult::Empty | db::prekeys::FetchResult::TargetDepleted) => None,
        Ok(db::prekeys::FetchResult::RateLimited) => {
            return error_429("pre-key fetch rate limit exceeded");
        }
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
pub(crate) async fn handle_upload(
    state: &AppState,
    user_id: &str,
    upload_id: MessageId,
    prekeys: Vec<OneTimePreKey>,
) -> ServerMessage {
    if prekeys.len() > consts::MAX_PREKEYS_PER_UPLOAD {
        return error_400("too many prekeys");
    }
    if prekeys.is_empty() {
        return error_400("prekey upload cannot be empty");
    }

    let pairs = match decode_prekeys(&prekeys) {
        Ok(p) => p,
        Err(msg) => return msg,
    };

    match db::prekeys::upload_prekeys(&state.db, user_id, &pairs, consts::MAX_PREKEYS_PER_USER)
        .await
    {
        Ok(db::prekeys::UploadResult::Accepted(remaining)) => ServerMessage::PreKeysUploaded {
            upload_id,
            accepted: true,
            remaining,
        },
        Ok(db::prekeys::UploadResult::InventoryFull(remaining)) => ServerMessage::PreKeysUploaded {
            upload_id,
            accepted: false,
            remaining,
        },
        Ok(db::prekeys::UploadResult::InvalidSequence) => {
            error_400("prekey IDs must increase monotonically")
        }
        Err(e) => {
            tracing::error!("failed to store prekeys: {e}");
            error_500_generic()
        }
    }
}

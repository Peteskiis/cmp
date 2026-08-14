use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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

pub(crate) async fn handle_signed_prekey_rotation(
    state: &AppState,
    user_id: &str,
    rotation_id: MessageId,
    key_id: u32,
    public_key: String,
    signature: String,
) -> ServerMessage {
    let (public_key, signature) =
        match validate_signed_prekey_rotation(state, user_id, &public_key, &signature).await {
            Ok(decoded) => decoded,
            Err(error) => return error,
        };
    store_signed_prekey_rotation(state, user_id, rotation_id, key_id, &public_key, &signature).await
}

async fn store_signed_prekey_rotation(
    state: &AppState,
    user_id: &str,
    rotation_id: MessageId,
    key_id: u32,
    public_key: &[u8],
    signature: &[u8],
) -> ServerMessage {
    let (accepted, previously_accepted, current_key_id) =
        match db::prekeys::rotate_signed_prekey(&state.db, user_id, key_id, public_key, signature)
            .await
        {
            Ok(db::prekeys::SignedPreKeyRotationResult::Accepted { current_key_id }) => {
                (true, false, current_key_id)
            }
            Ok(db::prekeys::SignedPreKeyRotationResult::PreviouslyAccepted { current_key_id }) => {
                (false, true, current_key_id)
            }
            Ok(
                db::prekeys::SignedPreKeyRotationResult::InvalidSequence { current_key_id }
                | db::prekeys::SignedPreKeyRotationResult::Conflict { current_key_id },
            ) => (false, false, current_key_id),
            Err(error) => {
                tracing::error!("failed to rotate signed prekey: {error}");
                return error_500_generic();
            }
        };
    ServerMessage::SignedPreKeyRotated {
        rotation_id,
        accepted,
        previously_accepted,
        current_key_id,
    }
}

#[allow(clippy::result_large_err)]
async fn validate_signed_prekey_rotation(
    state: &AppState,
    user_id: &str,
    public_key: &str,
    signature: &str,
) -> Result<([u8; 32], [u8; 64]), ServerMessage> {
    let (public_key, signature) = decode_signed_prekey(public_key, signature)?;
    let identity_key = match db::users::get_identity_key(&state.db, user_id).await {
        Ok(Some(key)) => key,
        Ok(None) => return Err(error_404("not found")),
        Err(error) => {
            tracing::error!("failed to load identity key: {error}");
            return Err(error_500_generic());
        }
    };
    verify_signed_prekey(user_id, &identity_key, &public_key, &signature)?;
    Ok((public_key, signature))
}

#[allow(clippy::result_large_err)]
fn decode_signed_prekey(
    public_key: &str,
    signature: &str,
) -> Result<([u8; 32], [u8; 64]), ServerMessage> {
    let public_key = B64
        .decode(public_key)
        .map_err(|_| error_400("invalid signed prekey encoding"))?
        .try_into()
        .map_err(|_| error_400("signed prekey must be 32 bytes"))?;
    let signature = B64
        .decode(signature)
        .map_err(|_| error_400("invalid signed prekey signature encoding"))?
        .try_into()
        .map_err(|_| error_400("signed prekey signature must be 64 bytes"))?;
    Ok((public_key, signature))
}

#[allow(clippy::result_large_err)]
fn verify_signed_prekey(
    user_id: &str,
    identity_key: &[u8],
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ServerMessage> {
    let identity_key: [u8; 32] = identity_key.try_into().map_err(|_| {
        tracing::error!(user_id, "stored identity key has invalid length");
        error_500_generic()
    })?;
    let verifying_key = VerifyingKey::from_bytes(&identity_key).map_err(|_| {
        tracing::error!(user_id, "stored identity key is invalid");
        error_500_generic()
    })?;
    verifying_key
        .verify(public_key, &Signature::from_bytes(signature))
        .map_err(|_| error_400("signed prekey signature is invalid"))
}

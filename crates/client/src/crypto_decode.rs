use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crypto::ratchet::RatchetHeader;
use protocol::types::RatchetHeader as ProtoRatchetHeader;

use crate::crypto_mgr::CryptoError;

pub(super) fn b64_decode_fixed<const N: usize>(
    encoded: &str,
    error: CryptoError,
) -> Result<[u8; N], CryptoError> {
    let bytes = B64.decode(encoded).map_err(|_| error)?;
    bytes.try_into().map_err(|_| CryptoError::BadBundle)
}

pub(super) fn decode_ratchet_header(
    proto: &ProtoRatchetHeader,
) -> Result<RatchetHeader, CryptoError> {
    Ok(RatchetHeader {
        ratchet_key: b64_decode_fixed::<32>(&proto.ratchet_key, CryptoError::BadEnvelope)?,
        previous_chain_length: proto.previous_chain_length,
        message_number: proto.message_number,
    })
}

//! Canonical associated-data context for encrypted envelopes.
//!
//! The Double Ratchet appends its fixed ratchet header to this context before
//! AEAD encryption. Keeping the envelope portion here gives every client one
//! byte-exact protocol encoding without depending on JSON serialization.

const DOMAIN: &[u8] = b"CMP_ENVELOPE_AAD";
const PREKEY_HEADER: u8 = 1;
const RATCHET_HEADER: u8 = 2;

fn prefix(version: u32, header_type: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN.len() + 5);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(&version.to_be_bytes());
    aad.push(header_type);
    aad
}

/// Context for an established-session ratchet envelope.
#[must_use]
pub fn ratchet(version: u32) -> Vec<u8> {
    prefix(version, RATCHET_HEADER)
}

/// Context for an X3DH first-message envelope.
#[must_use]
pub fn prekey(
    version: u32,
    sender_identity_key: &[u8; 32],
    sender_ephemeral_key: &[u8; 32],
    recipient_signed_prekey_id: u32,
    recipient_one_time_prekey_id: Option<u32>,
) -> Vec<u8> {
    let mut aad = prefix(version, PREKEY_HEADER);
    aad.extend_from_slice(sender_identity_key);
    aad.extend_from_slice(sender_ephemeral_key);
    aad.extend_from_slice(&recipient_signed_prekey_id.to_be_bytes());
    if let Some(key_id) = recipient_one_time_prekey_id {
        aad.push(1);
        aad.extend_from_slice(&key_id.to_be_bytes());
    } else {
        aad.push(0);
        aad.extend_from_slice(&0_u32.to_be_bytes());
    }
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_context_encoding_is_stable() {
        let mut ratchet_expected = b"CMP_ENVELOPE_AAD".to_vec();
        ratchet_expected.extend_from_slice(&2_u32.to_be_bytes());
        ratchet_expected.push(2);
        assert_eq!(ratchet(2), ratchet_expected);

        let mut prekey_expected = b"CMP_ENVELOPE_AAD".to_vec();
        prekey_expected.extend_from_slice(&2_u32.to_be_bytes());
        prekey_expected.push(1);
        prekey_expected.extend_from_slice(&[1; 32]);
        prekey_expected.extend_from_slice(&[2; 32]);
        prekey_expected.extend_from_slice(&0x0102_0304_u32.to_be_bytes());
        prekey_expected.push(1);
        prekey_expected.extend_from_slice(&0x0506_0708_u32.to_be_bytes());
        assert_eq!(
            prekey(2, &[1; 32], &[2; 32], 0x0102_0304, Some(0x0506_0708)),
            prekey_expected
        );

        let none_offset = prekey_expected.len() - 5;
        prekey_expected[none_offset..].copy_from_slice(&[0; 5]);
        assert_eq!(
            prekey(2, &[1; 32], &[2; 32], 0x0102_0304, None),
            prekey_expected
        );
    }

    #[test]
    fn every_semantic_field_changes_prekey_context() {
        let baseline = prekey(1, &[1; 32], &[2; 32], 3, Some(4));
        assert_ne!(baseline, prekey(2, &[1; 32], &[2; 32], 3, Some(4)));
        assert_ne!(baseline, prekey(1, &[9; 32], &[2; 32], 3, Some(4)));
        assert_ne!(baseline, prekey(1, &[1; 32], &[9; 32], 3, Some(4)));
        assert_ne!(baseline, prekey(1, &[1; 32], &[2; 32], 9, Some(4)));
        assert_ne!(baseline, prekey(1, &[1; 32], &[2; 32], 3, Some(9)));
        assert_ne!(baseline, prekey(1, &[1; 32], &[2; 32], 3, None));
        assert_ne!(baseline, ratchet(1));
    }
}

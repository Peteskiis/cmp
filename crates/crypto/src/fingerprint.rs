//! Safety number fingerprint computation (Signal-inspired iterated SHA-512).
//!
//! Produces a 60-digit numeric fingerprint from two users' identity keys.
//! Both parties compute the same value regardless of who is "local" vs "remote".

use sha2::{Digest, Sha512};

/// Number of SHA-512 iterations per user digest.
const ITERATIONS: u32 = 5200;

/// Version byte prepended to the first hash input.
const VERSION: u8 = 0x00;

/// A 60-digit safety number derived from two users' identity keys.
#[derive(Debug, PartialEq, Eq)]
pub struct Fingerprint {
    digits: [u8; 60],
}

impl Fingerprint {
    /// Compute a safety number from two `(user_id, identity_key)` pairs.
    ///
    /// The result is identical regardless of which pair is passed as "a" vs "b"
    /// — the pairs are sorted internally to guarantee symmetry.
    pub fn compute(user_a: &str, key_a: &[u8; 32], user_b: &str, key_b: &[u8; 32]) -> Self {
        // Sort by user_id (ties broken by key bytes) so both sides get the same order.
        let (first_id, first_key, second_id, second_key) =
            if (user_a, key_a.as_slice()) <= (user_b, key_b.as_slice()) {
                (user_a, key_a, user_b, key_b)
            } else {
                (user_b, key_b, user_a, key_a)
            };

        let first_digits = iterated_hash(first_id, first_key);
        let second_digits = iterated_hash(second_id, second_key);

        let mut digits = [0u8; 60];
        digits[..30].copy_from_slice(&first_digits);
        digits[30..].copy_from_slice(&second_digits);
        Self { digits }
    }

    /// Display as 12 groups of 5 digits separated by spaces.
    #[must_use]
    pub fn display_grouped(&self) -> String {
        let mut out = String::with_capacity(71); // 60 digits + 11 spaces
        for (i, &d) in self.digits.iter().enumerate() {
            if i > 0 && i % 5 == 0 {
                out.push(' ');
            }
            out.push(char::from(b'0' + d));
        }
        out
    }

    /// Raw digit array (each element is 0..=9).
    #[must_use]
    pub const fn as_digits(&self) -> &[u8; 60] {
        &self.digits
    }
}

/// Compute 30 decimal digits from a `(user_id, identity_key)` pair using
/// iterated SHA-512 (Signal-inspired `NumericFingerprint` variant).
fn iterated_hash(user_id: &str, identity_key: &[u8; 32]) -> [u8; 30] {
    // First iteration: SHA-512(version || identity_key || user_id)
    let mut hasher = Sha512::new();
    hasher.update([VERSION]);
    hasher.update(identity_key);
    hasher.update(user_id.as_bytes());
    let mut hash = hasher.finalize();

    // Remaining iterations: SHA-512(previous_hash || identity_key || user_id)
    for _ in 1..ITERATIONS {
        let mut hasher = Sha512::new();
        hasher.update(hash);
        hasher.update(identity_key);
        hasher.update(user_id.as_bytes());
        hash = hasher.finalize();
    }

    // Encode the first 30 bytes as 6 groups of 5 digits.
    let mut digits = [0u8; 30];
    for group in 0..6 {
        let offset = group * 5;
        // Read 5 bytes as big-endian integer, mod 100_000.
        let val = u64::from(hash[offset]) << 32
            | u64::from(hash[offset + 1]) << 24
            | u64::from(hash[offset + 2]) << 16
            | u64::from(hash[offset + 3]) << 8
            | u64::from(hash[offset + 4]);

        let mut rem = val % 100_000;
        let digit_offset = group * 5;
        for d in (0..5).rev() {
            #[allow(clippy::cast_possible_truncation)] // rem < 100_000, fits in u8
            {
                digits[digit_offset + d] = (rem % 10) as u8;
            }
            rem /= 10;
        }
    }
    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let fp1 = Fingerprint::compute("alice", &key_a, "bob", &key_b);
        let fp2 = Fingerprint::compute("alice", &key_a, "bob", &key_b);
        assert_eq!(fp1, fp2);
        // Verify display format: 12 groups of 5 digits, 11 spaces
        let display = fp1.display_grouped();
        let groups: Vec<&str> = display.split(' ').collect();
        assert_eq!(groups.len(), 12);
        for g in &groups {
            assert_eq!(g.len(), 5);
            assert!(g.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn symmetric() {
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        let fp_ab = Fingerprint::compute("alice", &key_a, "bob", &key_b);
        let fp_ba = Fingerprint::compute("bob", &key_b, "alice", &key_a);
        assert_eq!(
            fp_ab, fp_ba,
            "safety number must be identical regardless of argument order"
        );
    }

    #[test]
    fn different_keys_different_fingerprint() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let key_c = [3u8; 32];
        let fp1 = Fingerprint::compute("alice", &key_a, "bob", &key_b);
        let fp2 = Fingerprint::compute("alice", &key_a, "bob", &key_c);
        assert_ne!(
            fp1, fp2,
            "different keys must produce different fingerprints"
        );
    }

    #[test]
    fn different_user_ids_different_fingerprint() {
        let key = [0x42; 32];
        let fp1 = Fingerprint::compute("alice", &key, "bob", &key);
        let fp2 = Fingerprint::compute("alice", &key, "carol", &key);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn same_user_id_tie_broken_by_key() {
        // Edge case: self-chat or identical user IDs
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let fp1 = Fingerprint::compute("alice", &key_a, "alice", &key_b);
        let fp2 = Fingerprint::compute("alice", &key_b, "alice", &key_a);
        assert_eq!(fp1, fp2, "tie-breaking by key must be symmetric");
    }

    #[test]
    fn digits_in_range() {
        let fp = Fingerprint::compute("a", &[0xFF; 32], "b", &[0x00; 32]);
        for &d in fp.as_digits() {
            assert!(d <= 9, "each digit must be 0..=9, got {d}");
        }
    }
}

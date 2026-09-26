//! Key identifiers.
//!
//! Every key in NEXUS-Q has a [`KeyId`]: a stable, unique, public
//! identifier of the form `nqk_<algorithm>_<hex>`. The id reveals the
//! algorithm but no key material, and it is safe to log, display and
//! transmit.
//!
//! See `docs/KEY_MANAGEMENT.md` §3 for the rationale and the full
//! specification.

use std::fmt;
use std::str::FromStr;

use crate::crypto::random::{RandomError, RandomSource};

/// Number of random bytes carried by a [`KeyId`].
///
/// 16 bytes = 128 bits. Collision probability is negligible for any
/// realistic number of keys.
pub const RANDOM_BYTES: usize = 16;

/// Number of hex characters in the random part of a [`KeyId`].
pub const RANDOM_HEX_LEN: usize = RANDOM_BYTES * 2;

/// The literal prefix every [`KeyId`] starts with.
pub const PREFIX: &str = "nqk";

/// Errors returned when constructing or parsing a [`KeyId`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyIdError {
    /// The input did not start with the literal `nqk_` prefix.
    #[error("key id must start with `nqk_`")]
    MissingPrefix,

    /// The input contained fewer or more than three parts when split
    /// on underscores.
    #[error("key id must have exactly three underscore-separated parts")]
    MalformedParts,

    /// The algorithm segment was empty or contained disallowed
    /// characters.
    #[error("key id has an invalid algorithm segment")]
    InvalidAlgorithm,

    /// The random segment was not the expected length.
    #[error("key id random segment must be {RANDOM_HEX_LEN} hex characters")]
    InvalidRandomLength,

    /// The random segment contained non-hex characters.
    #[error("key id random segment contains non-hex characters")]
    InvalidRandomHex,

    /// The random source failed while generating a fresh id.
    #[error("failed to generate key id")]
    RandomFailure,
}

/// A stable, unique, public identifier for a NEXUS-Q key.
///
/// Layout: `nqk_<algorithm>_<hex>`.
///
/// The id is opaque: knowing it grants nothing. It is designed to be
/// embedded in metadata, log lines, and audit records.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Generates a fresh [`KeyId`] for `algorithm` using `source`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyIdError::RandomFailure`] if the underlying random
    /// source fails.
    pub fn generate<S: RandomSource>(source: &mut S, algorithm: &str) -> Result<Self, KeyIdError> {
        validate_algorithm_segment(algorithm)?;

        let mut buf = [0u8; RANDOM_BYTES];
        source
            .fill_bytes(&mut buf)
            .map_err(|_: RandomError| KeyIdError::RandomFailure)?;

        let mut out =
            String::with_capacity(PREFIX.len() + 1 + algorithm.len() + 1 + RANDOM_HEX_LEN);
        out.push_str(PREFIX);
        out.push('_');
        out.push_str(algorithm);
        out.push('_');
        push_hex(&mut out, &buf);

        Ok(Self(out))
    }

    /// Returns the algorithm segment of the id.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        // SAFETY of the split: the constructor guarantees exactly three
        // underscore-separated parts, so the second is always present.
        self.0.split('_').nth(1).unwrap_or("")
    }

    /// Returns the random hex segment of the id.
    #[must_use]
    pub fn random_part(&self) -> &str {
        self.0.split('_').nth(2).unwrap_or("")
    }

    /// Returns the id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.0)
    }
}

impl FromStr for KeyId {
    type Err = KeyIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (prefix, algorithm, random) = split_parts(s)?;
        if prefix != PREFIX {
            return Err(KeyIdError::MissingPrefix);
        }
        validate_algorithm_segment(algorithm)?;
        validate_random_segment(random)?;
        Ok(Self(s.to_string()))
    }
}

fn split_parts(s: &str) -> Result<(&str, &str, &str), KeyIdError> {
    let mut parts = s.split('_');
    let a = parts.next().ok_or(KeyIdError::MalformedParts)?;
    let b = parts.next().ok_or(KeyIdError::MalformedParts)?;
    let c = parts.next().ok_or(KeyIdError::MalformedParts)?;
    if parts.next().is_some() {
        return Err(KeyIdError::MalformedParts);
    }
    Ok((a, b, c))
}

fn validate_algorithm_segment(alg: &str) -> Result<(), KeyIdError> {
    if alg.is_empty() {
        return Err(KeyIdError::InvalidAlgorithm);
    }
    // Lowercase ASCII letters and digits only. Hyphens and uppercase
    // are deliberately disallowed: this segment appears in log lines
    // and identifiers should be boring.
    if !alg
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(KeyIdError::InvalidAlgorithm);
    }
    Ok(())
}

fn validate_random_segment(hex: &str) -> Result<(), KeyIdError> {
    if hex.len() != RANDOM_HEX_LEN {
        return Err(KeyIdError::InvalidRandomLength);
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(KeyIdError::InvalidRandomHex);
    }
    Ok(())
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;

    #[test]
    fn generate_produces_expected_shape() {
        let mut src = OsRandomSource::new();
        let id = KeyId::generate(&mut src, "mlkem768").unwrap();
        assert!(id.as_str().starts_with("nqk_mlkem768_"));
        assert_eq!(id.algorithm(), "mlkem768");
        assert_eq!(id.random_part().len(), RANDOM_HEX_LEN);
    }

    #[test]
    fn generate_produces_different_ids() {
        let mut src = OsRandomSource::new();
        let a = KeyId::generate(&mut src, "mlkem768").unwrap();
        let b = KeyId::generate(&mut src, "mlkem768").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn parse_accepts_example_from_docs() {
        let s = "nqk_mlkem768_7f3a9c2e4d1b8a6f5e0c3d9b2a1f4e7c";
        let id: KeyId = s.parse().unwrap();
        assert_eq!(id.as_str(), s);
        assert_eq!(id.algorithm(), "mlkem768");
        assert_eq!(id.random_part(), "7f3a9c2e4d1b8a6f5e0c3d9b2a1f4e7c");
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        let s = "nqx_mlkem768_7f3a9c2e4d1b8a6f5e0c3d9b2a1f4e7c";
        assert!(matches!(s.parse::<KeyId>(), Err(KeyIdError::MissingPrefix)));
    }

    #[test]
    fn parse_rejects_missing_parts() {
        assert!(matches!(
            "nqk_mlkem768".parse::<KeyId>(),
            Err(KeyIdError::MalformedParts)
        ));
    }

    #[test]
    fn parse_rejects_extra_parts() {
        assert!(matches!(
            "nqk_mlkem768_abc_def".parse::<KeyId>(),
            Err(KeyIdError::MalformedParts)
        ));
    }

    #[test]
    fn parse_rejects_short_random() {
        assert!(matches!(
            "nqk_mlkem768_abc".parse::<KeyId>(),
            Err(KeyIdError::InvalidRandomLength)
        ));
    }

    #[test]
    fn parse_rejects_non_hex_random() {
        let s = "nqk_mlkem768_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(matches!(
            s.parse::<KeyId>(),
            Err(KeyIdError::InvalidRandomHex)
        ));
    }

    #[test]
    fn parse_rejects_empty_algorithm() {
        let s = "nqk__7f3a9c2e4d1b8a6f5e0c3d9b2a1f4e7c";
        assert!(matches!(
            s.parse::<KeyId>(),
            Err(KeyIdError::InvalidAlgorithm)
        ));
    }

    #[test]
    fn parse_rejects_uppercase_algorithm() {
        let s = "nqk_MlKem768_7f3a9c2e4d1b8a6f5e0c3d9b2a1f4e7c";
        assert!(matches!(
            s.parse::<KeyId>(),
            Err(KeyIdError::InvalidAlgorithm)
        ));
    }

    #[test]
    fn display_and_parse_are_roundtrip() {
        let mut src = OsRandomSource::new();
        let id = KeyId::generate(&mut src, "ed25519").unwrap();
        let s = id.to_string();
        let parsed: KeyId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }
}

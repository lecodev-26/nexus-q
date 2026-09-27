//! Identity identifiers.
//!
//! An [`IdentityId`] is a stable, unique, public name for a NEXUS-Q
//! identity. It survives key rotation: when the signing key changes,
//! the identity keeps its id.
//!
//! Layout mirrors [`KeyId`](crate::vault::KeyId):
//!
//! ```text
//! nqi_<128-bit hex>
//! ```
//!
//! Unlike a KeyId, the id carries no algorithm segment: an identity is
//! an abstract subject, not a specific key. Its signing key is what
//! identifies it cryptographically.
//!
//! See ADR 0004.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::crypto::random::{RandomError, RandomSource};

/// Number of random bytes carried by an [`IdentityId`].
pub const RANDOM_BYTES: usize = 16;

/// Number of hex characters in the random part of an [`IdentityId`].
pub const RANDOM_HEX_LEN: usize = RANDOM_BYTES * 2;

/// The literal prefix every [`IdentityId`] starts with.
pub const PREFIX: &str = "nqi";

/// Errors returned when constructing or parsing an [`IdentityId`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityIdError {
    /// The input did not start with the literal `nqi_` prefix.
    #[error("identity id must start with `nqi_`")]
    MissingPrefix,

    /// The input contained more or fewer than two underscore-separated
    /// parts.
    #[error("identity id must have exactly two underscore-separated parts")]
    MalformedParts,

    /// The random segment was not the expected length.
    #[error("identity id random segment must be {RANDOM_HEX_LEN} hex characters")]
    InvalidRandomLength,

    /// The random segment contained non-hex characters.
    #[error("identity id random segment contains non-hex characters")]
    InvalidRandomHex,

    /// The random source failed while generating a fresh id.
    #[error("failed to generate identity id")]
    RandomFailure,
}

/// A stable, unique, public name for a NEXUS-Q identity.
///
/// Layout: `nqi_<hex>`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityId(String);

impl IdentityId {
    /// Generates a fresh [`IdentityId`] using `source`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityIdError::RandomFailure`] if the underlying
    /// random source fails.
    pub fn generate<S: RandomSource>(source: &S) -> Result<Self, IdentityIdError> {
        let mut buf = [0u8; RANDOM_BYTES];
        source
            .fill_bytes(&mut buf)
            .map_err(|_: RandomError| IdentityIdError::RandomFailure)?;

        let mut out = String::with_capacity(PREFIX.len() + 1 + RANDOM_HEX_LEN);
        out.push_str(PREFIX);
        out.push('_');
        push_hex(&mut out, &buf);

        Ok(Self(out))
    }

    /// Returns the random hex segment of the id.
    #[must_use]
    pub fn random_part(&self) -> &str {
        self.0.split('_').nth(1).unwrap_or("")
    }

    /// Returns the id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityId({})", self.0)
    }
}

impl FromStr for IdentityId {
    type Err = IdentityIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('_');
        let prefix = parts.next().ok_or(IdentityIdError::MalformedParts)?;
        let random = parts.next().ok_or(IdentityIdError::MalformedParts)?;
        if parts.next().is_some() {
            return Err(IdentityIdError::MalformedParts);
        }
        if prefix != PREFIX {
            return Err(IdentityIdError::MissingPrefix);
        }
        validate_random_segment(random)?;
        Ok(Self(s.to_string()))
    }
}

fn validate_random_segment(hex: &str) -> Result<(), IdentityIdError> {
    if hex.len() != RANDOM_HEX_LEN {
        return Err(IdentityIdError::InvalidRandomLength);
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(IdentityIdError::InvalidRandomHex);
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
        let rng = OsRandomSource::new();
        let id = IdentityId::generate(&rng).unwrap();
        assert!(id.as_str().starts_with("nqi_"));
        assert_eq!(id.random_part().len(), RANDOM_HEX_LEN);
    }

    #[test]
    fn generate_produces_different_ids() {
        let rng = OsRandomSource::new();
        let a = IdentityId::generate(&rng).unwrap();
        let b = IdentityId::generate(&rng).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn parse_accepts_valid_id() {
        let s = "nqi_7f3a9c2e4d1b8a6f5e0c3d9b2a1f4e7c";
        let id: IdentityId = s.parse().unwrap();
        assert_eq!(id.as_str(), s);
        assert_eq!(id.random_part(), "7f3a9c2e4d1b8a6f5e0c3d9b2a1f4e7c");
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        let s = "nqk_7f3a9c2e4d1b8a6f5e0c3d9b2a1f4e7c";
        assert!(matches!(
            s.parse::<IdentityId>(),
            Err(IdentityIdError::MissingPrefix)
        ));
    }

    #[test]
    fn parse_rejects_missing_parts() {
        assert!(matches!(
            "nqi".parse::<IdentityId>(),
            Err(IdentityIdError::MalformedParts)
        ));
        assert!(matches!(
            "nqi_".parse::<IdentityId>(),
            Err(IdentityIdError::InvalidRandomLength)
        ));
    }

    #[test]
    fn parse_rejects_extra_parts() {
        assert!(matches!(
            "nqi_abc_def".parse::<IdentityId>(),
            Err(IdentityIdError::MalformedParts)
        ));
    }

    #[test]
    fn parse_rejects_short_random() {
        assert!(matches!(
            "nqi_abc".parse::<IdentityId>(),
            Err(IdentityIdError::InvalidRandomLength)
        ));
    }

    #[test]
    fn parse_rejects_non_hex_random() {
        let s = "nqi_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(matches!(
            s.parse::<IdentityId>(),
            Err(IdentityIdError::InvalidRandomHex)
        ));
    }

    #[test]
    fn display_and_parse_are_roundtrip() {
        let rng = OsRandomSource::new();
        let id = IdentityId::generate(&rng).unwrap();
        let s = id.to_string();
        let parsed: IdentityId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }
}

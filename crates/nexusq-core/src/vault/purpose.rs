//! Purposes a key can be created for.
//!
//! A key is bound to exactly one purpose at creation. A signing key
//! cannot be used to wrap data keys; a KEM key cannot sign documents.
//! The vault enforces this, and the policy engine enforces it further.
//!
//! See `docs/KEY_MANAGEMENT.md` §4 and §6.2.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::Algorithm;

/// What a key is allowed to be used for.
///
/// Purposes are disjoint: a single key has exactly one purpose, and
/// no key can be used outside of it. This limits the blast radius of
/// any single key compromise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Produce signatures (documents, messages, credentials).
    Sign,
    /// Encrypt data with a long-lived key.
    ///
    /// Rare in practice: most encryption uses a per-envelope key that
    /// is itself wrapped. This purpose exists for cases where a single
    /// long-lived symmetric key is required.
    Encrypt,
    /// Decrypt data with a long-lived key.
    Decrypt,
    /// Establish a shared secret with a peer (KEM).
    KeyAgreement,
    /// Wrap and unwrap other keys.
    Wrap,
}

impl Purpose {
    /// Returns the canonical lowercase identifier of this purpose.
    ///
    /// This is the string used in serialized metadata. It is stable:
    /// changing it is a breaking change.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::KeyAgreement => "key_agreement",
            Self::Wrap => "wrap",
        }
    }

    /// Returns `true` if this purpose is allowed for `algorithm`.
    #[must_use]
    pub fn is_allowed_for(self, algorithm: Algorithm) -> bool {
        algorithm.allowed_purposes().contains(&self)
    }

    /// Returns every purpose known to the key manager.
    #[must_use]
    pub const fn all() -> &'static [Purpose] {
        &[
            Purpose::Sign,
            Purpose::Encrypt,
            Purpose::Decrypt,
            Purpose::KeyAgreement,
            Purpose::Wrap,
        ]
    }
}

impl Serialize for Purpose {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Purpose {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Purpose {
    type Err = PurposeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for &p in Purpose::all() {
            if p.as_str() == s {
                return Ok(p);
            }
        }
        Err(PurposeError::Unknown(s.to_string()))
    }
}

/// Errors returned when parsing a [`Purpose`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PurposeError {
    /// The input did not match any known purpose identifier.
    #[error("unknown purpose: {0}")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_display_and_parse_for_every_purpose() {
        for &p in Purpose::all() {
            let s = p.to_string();
            let parsed: Purpose = s.parse().unwrap();
            assert_eq!(parsed, p);
        }
    }

    #[test]
    fn canonical_strings_are_stable() {
        assert_eq!(Purpose::Sign.as_str(), "sign");
        assert_eq!(Purpose::Encrypt.as_str(), "encrypt");
        assert_eq!(Purpose::Decrypt.as_str(), "decrypt");
        assert_eq!(Purpose::KeyAgreement.as_str(), "key_agreement");
        assert_eq!(Purpose::Wrap.as_str(), "wrap");
    }

    #[test]
    fn parse_rejects_unknown() {
        assert!(matches!(
            "hash".parse::<Purpose>(),
            Err(PurposeError::Unknown(_))
        ));
    }

    #[test]
    fn parse_rejects_case_variants() {
        assert!("Sign".parse::<Purpose>().is_err());
        assert!("SIGN".parse::<Purpose>().is_err());
    }
}

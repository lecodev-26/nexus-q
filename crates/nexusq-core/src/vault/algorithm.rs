//! Cryptographic algorithms recognized by the key manager.
//!
//! This enum is descriptive: it names the algorithms NEXUS-Q knows how
//! to use, along with their canonical string identifiers and key sizes.
//! It does not perform any cryptographic operations. The vault module
//! maps each variant to the corresponding implementation in
//! [`crate::crypto`].
//!
//! Only algorithms that are already implemented are listed here. New
//! variants are added when a primitive lands, not in advance. See
//! `docs/CRYPTOGRAPHY.md` §4 for the full set of algorithm families
//! and their parameters.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::Purpose;

/// Category of a cryptographic algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// Key encapsulation mechanism (post-quantum).
    Kem,
    /// Digital signature scheme.
    Signature,
    /// Authenticated symmetric encryption.
    Aead,
}

/// A cryptographic algorithm supported by NEXUS-Q.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ML-KEM-768 (FIPS 203). Post-quantum key encapsulation.
    MlKem768,
    /// ML-KEM-1024 (FIPS 203). Post-quantum key encapsulation.
    MlKem1024,
    /// Ed25519 (RFC 8032). Digital signatures.
    Ed25519,
    /// ML-DSA-65 (FIPS 204). Post-quantum digital signatures.
    MlDsa65,
    /// SLH-DSA-SHAKE-128f (FIPS 205). Hash-based post-quantum signatures.
    SlhDsaShake128f,
    /// AES-256-GCM (NIST SP 800-38D). Authenticated encryption.
    Aes256Gcm,
    /// ChaCha20-Poly1305 (RFC 8439). Authenticated encryption.
    ChaCha20Poly1305,
}

impl Algorithm {
    /// Returns the canonical lowercase identifier of this algorithm.
    ///
    /// This is the string used in [`crate::vault::KeyId`] and in any
    /// serialized metadata. It is stable: changing it is a breaking
    /// change.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MlKem768 => "mlkem768",
            Self::MlKem1024 => "mlkem1024",
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "mldsa65",
            Self::SlhDsaShake128f => "slhdsa-shake128f",
            Self::Aes256Gcm => "aes256gcm",
            Self::ChaCha20Poly1305 => "chacha20poly1305",
        }
    }

    /// Returns the category this algorithm belongs to.
    #[must_use]
    pub const fn category(self) -> Category {
        match self {
            Self::MlKem768 | Self::MlKem1024 => Category::Kem,
            Self::Ed25519 | Self::MlDsa65 | Self::SlhDsaShake128f => Category::Signature,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => Category::Aead,
        }
    }

    /// Returns the length in bytes of a public key for this algorithm,
    /// or `None` if the algorithm has no public key.
    #[must_use]
    pub const fn public_key_len(self) -> Option<usize> {
        match self {
            Self::MlKem768 => Some(1184 + 32),
            Self::MlKem1024 => Some(1568 + 32),
            Self::Ed25519 => Some(32),
            Self::MlDsa65 => Some(crate::crypto::pq_sign::ML_DSA_65_PUBLIC_KEY_LEN),
            Self::SlhDsaShake128f => {
                Some(crate::crypto::pq_sign::SLH_DSA_SHAKE_128F_PUBLIC_KEY_LEN)
            }
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => None,
        }
    }

    /// Returns the length in bytes of a secret key for this algorithm.
    #[must_use]
    pub const fn secret_key_len(self) -> Option<usize> {
        match self {
            Self::MlKem768 | Self::MlKem1024 => Some(96),
            Self::Ed25519 => Some(32),
            Self::MlDsa65 => Some(crate::crypto::pq_sign::ML_DSA_65_SECRET_KEY_LEN),
            Self::SlhDsaShake128f => {
                Some(crate::crypto::pq_sign::SLH_DSA_SHAKE_128F_SECRET_KEY_LEN)
            }
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => Some(32),
        }
    }

    /// Returns the set of purposes a key with this algorithm can be
    /// created for.
    ///
    /// A key with an algorithm but no matching purpose is rejected at
    /// creation time.
    #[must_use]
    pub const fn allowed_purposes(self) -> &'static [Purpose] {
        match self {
            Self::MlKem768 | Self::MlKem1024 => &[Purpose::KeyAgreement],
            Self::Ed25519 | Self::MlDsa65 | Self::SlhDsaShake128f => &[Purpose::Sign],
            Self::Aes256Gcm => &[Purpose::Encrypt, Purpose::Decrypt, Purpose::Wrap],
            Self::ChaCha20Poly1305 => &[Purpose::Encrypt, Purpose::Decrypt],
        }
    }

    /// Returns every algorithm known to the key manager.
    #[must_use]
    pub const fn all() -> &'static [Algorithm] {
        &[
            Algorithm::MlKem768,
            Algorithm::MlKem1024,
            Algorithm::Ed25519,
            Algorithm::MlDsa65,
            Algorithm::SlhDsaShake128f,
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
        ]
    }
}

impl Serialize for Algorithm {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = AlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for &alg in Algorithm::all() {
            if alg.as_str() == s {
                return Ok(alg);
            }
        }
        Err(AlgorithmError::Unknown(s.to_string()))
    }
}

/// Errors returned when parsing an [`Algorithm`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AlgorithmError {
    /// The input did not match any known algorithm identifier.
    #[error("unknown algorithm: {0}")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_display_and_parse_for_every_algorithm() {
        for &alg in Algorithm::all() {
            let s = alg.to_string();
            let parsed: Algorithm = s.parse().unwrap();
            assert_eq!(parsed, alg);
        }
    }

    #[test]
    fn categories_are_correct() {
        assert_eq!(Algorithm::MlKem768.category(), Category::Kem);
        assert_eq!(Algorithm::Ed25519.category(), Category::Signature);
        assert_eq!(Algorithm::Aes256Gcm.category(), Category::Aead);
        assert_eq!(Algorithm::ChaCha20Poly1305.category(), Category::Aead);
    }

    #[test]
    fn public_key_lengths_match_specs() {
        assert_eq!(Algorithm::MlKem768.public_key_len(), Some(1216));
        assert_eq!(Algorithm::MlKem1024.public_key_len(), Some(1600));
        assert_eq!(Algorithm::MlDsa65.public_key_len(), Some(1952));
        assert_eq!(Algorithm::SlhDsaShake128f.public_key_len(), Some(32));
        assert_eq!(Algorithm::Ed25519.public_key_len(), Some(32));
        assert_eq!(Algorithm::Aes256Gcm.public_key_len(), None);
        assert_eq!(Algorithm::ChaCha20Poly1305.public_key_len(), None);
    }

    #[test]
    fn secret_key_lengths_match_specs() {
        assert_eq!(Algorithm::MlKem768.secret_key_len(), Some(96));
        assert_eq!(Algorithm::MlKem1024.secret_key_len(), Some(96));
        assert_eq!(Algorithm::MlDsa65.secret_key_len(), Some(32));
        assert_eq!(Algorithm::SlhDsaShake128f.secret_key_len(), Some(64));
        assert_eq!(Algorithm::Ed25519.secret_key_len(), Some(32));
        assert_eq!(Algorithm::Aes256Gcm.secret_key_len(), Some(32));
        assert_eq!(Algorithm::ChaCha20Poly1305.secret_key_len(), Some(32));
    }

    #[test]
    fn canonical_strings_are_stable() {
        // These strings appear in KeyId and in serialized metadata.
        // Changing any of them is a breaking change.
        assert_eq!(Algorithm::MlKem768.as_str(), "mlkem768");
        assert_eq!(Algorithm::MlKem1024.as_str(), "mlkem1024");
        assert_eq!(Algorithm::MlDsa65.as_str(), "mldsa65");
        assert_eq!(Algorithm::SlhDsaShake128f.as_str(), "slhdsa-shake128f");
        assert_eq!(Algorithm::Ed25519.as_str(), "ed25519");
        assert_eq!(Algorithm::Aes256Gcm.as_str(), "aes256gcm");
        assert_eq!(Algorithm::ChaCha20Poly1305.as_str(), "chacha20poly1305");
    }

    #[test]
    fn parse_rejects_unknown() {
        assert!(matches!(
            "rsa2048".parse::<Algorithm>(),
            Err(AlgorithmError::Unknown(_))
        ));
    }

    #[test]
    fn parse_rejects_case_variants() {
        assert!("MLKEM768".parse::<Algorithm>().is_err());
        assert!("mldsa65".parse::<Algorithm>().is_ok());
        assert!("Ed25519".parse::<Algorithm>().is_err());
    }

    #[test]
    fn allowed_purposes_are_correct_per_algorithm() {
        assert_eq!(
            Algorithm::MlKem768.allowed_purposes(),
            &[Purpose::KeyAgreement]
        );
        assert_eq!(Algorithm::Ed25519.allowed_purposes(), &[Purpose::Sign]);
        assert_eq!(
            Algorithm::Aes256Gcm.allowed_purposes(),
            &[Purpose::Encrypt, Purpose::Decrypt, Purpose::Wrap]
        );
        assert_eq!(
            Algorithm::ChaCha20Poly1305.allowed_purposes(),
            &[Purpose::Encrypt, Purpose::Decrypt]
        );
    }

    #[test]
    fn purpose_matches_algorithm_consistently() {
        assert!(Purpose::Sign.is_allowed_for(Algorithm::Ed25519));
        assert!(Purpose::Sign.is_allowed_for(Algorithm::MlDsa65));
        assert!(Purpose::Sign.is_allowed_for(Algorithm::SlhDsaShake128f));
        assert!(!Purpose::Sign.is_allowed_for(Algorithm::MlKem768));
        assert!(Purpose::KeyAgreement.is_allowed_for(Algorithm::MlKem768));
        assert!(Purpose::KeyAgreement.is_allowed_for(Algorithm::MlKem1024));
        assert!(!Purpose::KeyAgreement.is_allowed_for(Algorithm::Ed25519));
        assert!(Purpose::Wrap.is_allowed_for(Algorithm::Aes256Gcm));
        assert!(!Purpose::Wrap.is_allowed_for(Algorithm::ChaCha20Poly1305));
    }
}

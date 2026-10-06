//! Vault file header.
//!
//! The header is the cleartext, authenticated prefix of a vault file
//! (format F-01, `docs/STORAGE.md` §4.1). It carries everything needed
//! to derive the Key Encryption Key (KEK) and to verify that the
//! password is correct, *before* attempting to decrypt the body.
//!
//! ## Layout
//!
//! The entire header is serialized as a single CBOR map. That choice
//! (see ADR 0002) keeps the layout self-describing and lets us evolve
//! it later without changing the file's magic or version.
//!
//! ## Authentication
//!
//! The header is not encrypted, but it is authenticated: the AEAD tag
//! of the body is computed with the header's CBOR bytes as Associated
//! Data (AAD). Modifying any header field invalidates the body's tag.
//!
//! ## KEK verifier
//!
//! The `kek_verifier` field lets the vault reject a wrong password
//! without decrypting the body. It is computed as
//! `HKDF-SHA256(ikm = KEK, salt = none, info = "nexusq-kek-check", L = 32)`.
//! Because HKDF is deterministic, the same KEK always yields the same
//! verifier, and any wrong KEK yields a different one with overwhelming
//! probability.

use serde::{Deserialize, Serialize};

use crate::crypto::kdf::{KdfError, hkdf_sha256};

/// File magic for the vault format.
pub const MAGIC: [u8; 4] = *b"NQV1";

/// Current file format version.
pub const FORMAT_VERSION: u8 = 1;

/// Length in bytes of the Argon2id salt.
pub const SALT_LEN: usize = 32;

/// Length in bytes of the KEK verifier.
pub const KEK_VERIFIER_LEN: usize = 32;

/// Info string for the KEK verifier derivation.
const KEK_VERIFIER_INFO: &[u8] = b"nexusq-kek-check";

/// Identifier of the KDF algorithm used to derive the KEK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    /// Argon2id, as specified in `docs/CRYPTOGRAPHY.md` §4.3.
    #[serde(rename = "argon2id")]
    Argon2id,
}

impl KdfAlgorithm {
    /// Returns the canonical lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Argon2id => "argon2id",
        }
    }
}

/// Parameters for the Key Derivation Function.
///
/// Stored in cleartext because the attacker already knows what function
/// we use; hiding it would only obscure the format without adding
/// security. Storing it in the header means we can upgrade the cost
/// parameters when the vault is re-encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Which algorithm to use.
    pub algorithm: KdfAlgorithm,
    /// Memory cost in kibibytes.
    pub memory_kib: u32,
    /// Number of iterations.
    pub iterations: u32,
    /// Parallelism factor.
    pub parallelism: u32,
    /// Output length in bytes.
    pub output_len: u32,
}

impl KdfParams {
    /// Returns the v1 default parameters, matching
    /// `docs/CRYPTOGRAPHY.md` §4.3.
    #[must_use]
    pub const fn v1_default() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: crate::crypto::kdf::ARGON2_MEMORY_KIB,
            iterations: crate::crypto::kdf::ARGON2_ITERATIONS,
            parallelism: crate::crypto::kdf::ARGON2_PARALLELISM,
            output_len: crate::crypto::kdf::DERIVED_KEY_LEN as u32,
        }
    }
}

/// The vault file header.
///
/// Serialized to CBOR and stored at the start of the vault file. Every
/// field is also part of the AEAD AAD of the body, so tampering with
/// any of them is detectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    /// File magic: always [`MAGIC`].
    pub magic: [u8; 4],

    /// File format version: always [`FORMAT_VERSION`] for v1.
    pub version: u8,

    /// Reserved flags. Must be zero in v1.
    pub flags: u16,

    /// Key derivation parameters.
    pub kdf: KdfParams,

    /// Random salt, unique per vault.
    pub salt: Vec<u8>,

    /// Verifier for the derived KEK.
    pub kek_verifier: [u8; KEK_VERIFIER_LEN],
}

impl VaultHeader {
    /// Creates a header for a new vault.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError`] if the salt has the wrong length or if
    /// the verifier cannot be computed.
    pub fn new(kdf: KdfParams, salt: Vec<u8>, kek: &[u8]) -> Result<Self, HeaderError> {
        if salt.len() != SALT_LEN {
            return Err(HeaderError::InvalidSaltLength);
        }

        let verifier = compute_kek_verifier(kek)?;

        Ok(Self {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            kdf,
            salt,
            kek_verifier: verifier,
        })
    }

    /// Returns `true` if the header's magic and version match what this
    /// build supports.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.magic == MAGIC && self.version == FORMAT_VERSION && self.flags == 0
    }

    /// Checks that `kek` produces the same verifier stored in the header.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::WrongPassword`] if the derived verifier
    /// does not match, and [`HeaderError::Kdf`] if the derivation fails.
    pub fn verify_kek(&self, kek: &[u8]) -> Result<(), HeaderError> {
        let computed = compute_kek_verifier(kek)?;
        if computed == self.kek_verifier {
            Ok(())
        } else {
            Err(HeaderError::WrongPassword)
        }
    }
}

fn compute_kek_verifier(kek: &[u8]) -> Result<[u8; KEK_VERIFIER_LEN], HeaderError> {
    let mut verifier = [0u8; KEK_VERIFIER_LEN];
    let derived = hkdf_sha256(kek, None, KEK_VERIFIER_INFO).map_err(HeaderError::Kdf)?;
    verifier.copy_from_slice(&*derived);
    Ok(verifier)
}

/// Errors returned by header operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HeaderError {
    /// The salt length was not [`SALT_LEN`].
    #[error("invalid salt length")]
    InvalidSaltLength,

    /// The password did not match the verifier.
    #[error("wrong password")]
    WrongPassword,

    /// The underlying KDF failed.
    #[error("kdf failure")]
    Kdf(#[source] KdfError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_kek() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn sample_header() -> VaultHeader {
        VaultHeader::new(KdfParams::v1_default(), vec![0u8; SALT_LEN], &sample_kek()).unwrap()
    }

    #[test]
    fn new_header_has_expected_magic_and_version() {
        let h = sample_header();
        assert_eq!(h.magic, MAGIC);
        assert_eq!(h.version, FORMAT_VERSION);
        assert_eq!(h.flags, 0);
    }

    #[test]
    fn new_header_rejects_short_salt() {
        let err =
            VaultHeader::new(KdfParams::v1_default(), vec![0u8; 8], &sample_kek()).unwrap_err();
        assert!(matches!(err, HeaderError::InvalidSaltLength));
    }

    #[test]
    fn verify_kek_accepts_correct_kek() {
        let h = sample_header();
        assert!(h.verify_kek(&sample_kek()).is_ok());
    }

    #[test]
    fn verify_kek_rejects_wrong_kek() {
        let h = sample_header();
        let wrong = [0x43u8; 32];
        assert!(matches!(
            h.verify_kek(&wrong),
            Err(HeaderError::WrongPassword)
        ));
    }

    #[test]
    fn same_kek_produces_same_verifier() {
        let h1 =
            VaultHeader::new(KdfParams::v1_default(), vec![1u8; SALT_LEN], &sample_kek()).unwrap();
        let h2 =
            VaultHeader::new(KdfParams::v1_default(), vec![2u8; SALT_LEN], &sample_kek()).unwrap();
        // The verifier depends only on the KEK, not on the salt.
        // (The salt is used when deriving the KEK from the password.)
        assert_eq!(h1.kek_verifier, h2.kek_verifier);
    }

    #[test]
    fn different_kek_produces_different_verifier() {
        let kek_a = [0x01u8; 32];
        let kek_b = [0x02u8; 32];
        let h_a = VaultHeader::new(KdfParams::v1_default(), vec![0u8; SALT_LEN], &kek_a).unwrap();
        let h_b = VaultHeader::new(KdfParams::v1_default(), vec![0u8; SALT_LEN], &kek_b).unwrap();
        assert_ne!(h_a.kek_verifier, h_b.kek_verifier);
    }

    #[test]
    fn is_supported_true_for_v1_header() {
        assert!(sample_header().is_supported());
    }

    #[test]
    fn is_supported_false_for_wrong_magic() {
        let mut h = sample_header();
        h.magic = *b"XXXX";
        assert!(!h.is_supported());
    }

    #[test]
    fn is_supported_false_for_wrong_version() {
        let mut h = sample_header();
        h.version = 99;
        assert!(!h.is_supported());
    }

    #[test]
    fn is_supported_false_for_nonzero_flags() {
        let mut h = sample_header();
        h.flags = 1;
        assert!(!h.is_supported());
    }

    #[test]
    fn kdf_params_v1_default_matches_cryptography_md() {
        let p = KdfParams::v1_default();
        assert_eq!(p.algorithm, KdfAlgorithm::Argon2id);
        assert_eq!(p.memory_kib, 64 * 1024);
        assert_eq!(p.iterations, 3);
        assert_eq!(p.parallelism, 1);
        assert_eq!(p.output_len, 32);
    }

    #[test]
    fn kdf_algorithm_strings_are_stable() {
        assert_eq!(KdfAlgorithm::Argon2id.as_str(), "argon2id");
    }
}

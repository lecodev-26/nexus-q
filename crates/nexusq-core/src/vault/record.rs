//! Key records.
//!
//! A [`KeyRecord`] is what actually lives in the vault: the metadata
//! describing a key, plus the key material itself, wrapped under the
//! vault's Key Encryption Key (KEK).
//!
//! The material is always stored wrapped. Nothing in this module ever
//! sees plaintext key bytes; the vault (later phase) is responsible for
//! unwrapping into a session before use and re-wrapping on write.
//!
//! See `docs/KEY_MANAGEMENT.md` §4 and `docs/STORAGE.md` §4.

use super::{Algorithm, KeyId, KeyMetadata, KeyStatus, Purpose};

/// Key material wrapped under the vault's KEK.
///
/// The three variants describe *what kind* of material is stored, so
/// that the vault can apply the right size and shape checks without
/// having to know the algorithm in advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrappedKeyMaterial {
    /// Symmetric key material (AES, ChaCha20).
    ///
    /// Fixed length for the algorithms NEXUS-Q supports; the vault
    /// checks it against the algorithm's `secret_key_len`.
    Symmetric(Vec<u8>),

    /// Private key material for an asymmetric algorithm (Ed25519,
    /// ML-KEM, and later ML-DSA).
    Asymmetric(Vec<u8>),

    /// Reference to a key that lives in hardware (TPM, HSM, SE).
    ///
    /// The vault never sees the raw private key for these; it stores
    /// only an opaque handle that the hardware backend understands.
    HardwareHandle(Vec<u8>),
}

impl WrappedKeyMaterial {
    /// Returns the wrapped bytes, whatever the variant.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Symmetric(b) | Self::Asymmetric(b) | Self::HardwareHandle(b) => b,
        }
    }

    /// Returns the length in bytes of the wrapped material.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// Returns `true` if the wrapped material is empty.
    ///
    /// Empty wrapped material is never valid in the vault; this
    /// helper exists for callers to assert.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }

    /// Returns a short tag naming the variant, for diagnostics and
    /// audit records.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Symmetric(_) => "symmetric",
            Self::Asymmetric(_) => "asymmetric",
            Self::HardwareHandle(_) => "hardware_handle",
        }
    }
}

/// A key in the vault: metadata plus wrapped material.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    /// Everything the vault knows about the key, except the material.
    pub metadata: KeyMetadata,

    /// The key material, wrapped under the vault's KEK.
    pub material: WrappedKeyMaterial,
}

impl KeyRecord {
    /// Creates a new record from its two halves.
    #[must_use]
    pub fn new(metadata: KeyMetadata, material: WrappedKeyMaterial) -> Self {
        Self { metadata, material }
    }

    /// Returns the key's id.
    #[must_use]
    pub fn key_id(&self) -> &KeyId {
        &self.metadata.key_id
    }

    /// Returns the key's algorithm.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.metadata.algorithm
    }

    /// Returns the key's purpose.
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        self.metadata.purpose
    }

    /// Returns the key's current status.
    #[must_use]
    pub fn status(&self) -> KeyStatus {
        self.metadata.status
    }

    /// Returns `true` if the key can currently produce new signatures
    /// or new ciphertexts.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.metadata.is_active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;
    use crate::vault::{Origin, Timestamp};

    fn sample_metadata() -> KeyMetadata {
        let mut src = OsRandomSource::new();
        let key_id = KeyId::generate(&mut src, "ed25519").unwrap();
        KeyMetadata {
            key_id,
            algorithm: Algorithm::Ed25519,
            purpose: Purpose::Sign,
            created_at: Timestamp::from_secs(1_700_000_000),
            created_by: "test".to_string(),
            created_from: Origin::Generated,
            status: KeyStatus::Active,
            version: 1,
            owner: None,
            rotation_due: None,
            expires_at: None,
            parent_key_id: None,
            hardware_backed: false,
            attestation: None,
        }
    }

    #[test]
    fn record_exposes_metadata_fields() {
        let md = sample_metadata();
        let expected_id = md.key_id.clone();
        let record = KeyRecord::new(md, WrappedKeyMaterial::Asymmetric(vec![0u8; 64]));

        assert_eq!(record.key_id(), &expected_id);
        assert_eq!(record.algorithm(), Algorithm::Ed25519);
        assert_eq!(record.purpose(), Purpose::Sign);
        assert_eq!(record.status(), KeyStatus::Active);
        assert!(record.is_active());
    }

    #[test]
    fn wrapped_material_reports_kind() {
        let m = WrappedKeyMaterial::Symmetric(vec![0u8; 32]);
        assert_eq!(m.kind(), "symmetric");
        let m = WrappedKeyMaterial::Asymmetric(vec![0u8; 64]);
        assert_eq!(m.kind(), "asymmetric");
        let m = WrappedKeyMaterial::HardwareHandle(vec![1, 2, 3]);
        assert_eq!(m.kind(), "hardware_handle");
    }

    #[test]
    fn wrapped_material_bytes_and_length() {
        let m = WrappedKeyMaterial::Symmetric(vec![1, 2, 3, 4]);
        assert_eq!(m.len(), 4);
        assert_eq!(m.bytes(), &[1, 2, 3, 4]);
        assert!(!m.is_empty());
    }

    #[test]
    fn wrapped_material_empty_check() {
        let m = WrappedKeyMaterial::Asymmetric(Vec::new());
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn record_is_cloneable() {
        let md = sample_metadata();
        let record = KeyRecord::new(md, WrappedKeyMaterial::Asymmetric(vec![0u8; 64]));
        let cloned = record.clone();
        assert_eq!(cloned.key_id(), record.key_id());
        assert_eq!(cloned.material, record.material);
    }

    #[test]
    fn record_inactive_when_metadata_status_disallows_work() {
        let mut md = sample_metadata();
        md.status = KeyStatus::Retired;
        let record = KeyRecord::new(md, WrappedKeyMaterial::Asymmetric(vec![0u8; 64]));
        assert!(!record.is_active());
    }
}

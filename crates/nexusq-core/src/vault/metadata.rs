//! Key metadata.
//!
//! Every key in the vault is described by a [`KeyMetadata`] record.
//! The metadata is authenticated (bound to the vault's AEAD tag or MAC)
//! but never secret: an attacker with disk access can read it.
//!
//! Metadata is not an authorization source. It records intent and
//! history; the policy engine (later phase) decides what may actually
//! be done with a key.
//!
//! See `docs/KEY_MANAGEMENT.md` §4.

use super::{Algorithm, KeyId, KeyStatus, Purpose, Timestamp};

/// How a key came to exist in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// Created by NEXUS-Q itself.
    Generated,
    /// Imported from an external source.
    Imported,
    /// Derived from another key (see `parent_key_id`).
    Derived,
}

impl Origin {
    /// Returns the canonical lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generated => "generated",
            Self::Imported => "imported",
            Self::Derived => "derived",
        }
    }
}

/// Everything the vault knows about a key, except the key material.
///
/// The key material lives separately, wrapped under the vault's KEK.
/// This struct is the "public face" of a key inside the vault.
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    /// Unique identifier. Never changes for the lifetime of the key.
    pub key_id: KeyId,

    /// Cryptographic algorithm.
    pub algorithm: Algorithm,

    /// What the key is allowed to be used for.
    pub purpose: Purpose,

    /// When the key was created.
    pub created_at: Timestamp,

    /// Free-form identifier of who or what created the key.
    ///
    /// Will become a typed `IdentityId` when identities land (Fase 6).
    pub created_by: String,

    /// How the key came to exist.
    pub created_from: Origin,

    /// Current lifecycle state.
    pub status: KeyStatus,

    /// Rotation generation, starting at 1.
    ///
    /// When a key is rotated, the replacement starts at `version + 1`
    /// while the original remains at its own version.
    pub version: u32,

    /// Optional owner responsible for this key.
    ///
    /// Will become a typed `IdentityId` when identities land (Fase 6).
    pub owner: Option<String>,

    /// Optional deadline by which the key should be rotated.
    pub rotation_due: Option<Timestamp>,

    /// Optional hard expiration date.
    ///
    /// Past this instant the key must not be used for new work.
    pub expires_at: Option<Timestamp>,

    /// For derived keys, the id of the key they came from.
    pub parent_key_id: Option<KeyId>,

    /// Whether the private half lives in hardware (TPM, SE, HSM).
    ///
    /// When true the vault stores only a handle, never the raw key.
    pub hardware_backed: bool,

    /// Optional attestation evidence for hardware-backed keys.
    ///
    /// Opaque to the core; interpreted in Fase 7 and later.
    pub attestation: Option<Vec<u8>>,
}

impl KeyMetadata {
    /// Returns `true` if the key can currently be used for new
    /// signatures or new ciphertexts.
    ///
    /// This method checks only the key's own state. Authorization is a
    /// separate concern handled by the policy engine.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.is_usable_for_new_work()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;

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
    fn is_active_when_status_allows_new_work() {
        let md = sample_metadata();
        assert!(md.is_active());
    }

    #[test]
    fn is_not_active_when_status_disallows_new_work() {
        let mut md = sample_metadata();
        md.status = KeyStatus::Retired;
        assert!(!md.is_active());
    }

    #[test]
    fn origin_strings_are_stable() {
        assert_eq!(Origin::Generated.as_str(), "generated");
        assert_eq!(Origin::Imported.as_str(), "imported");
        assert_eq!(Origin::Derived.as_str(), "derived");
    }

    #[test]
    fn metadata_is_cloneable() {
        let md = sample_metadata();
        let cloned = md.clone();
        assert_eq!(cloned.key_id, md.key_id);
        assert_eq!(cloned.algorithm, md.algorithm);
        assert_eq!(cloned.status, md.status);
    }

    #[test]
    fn metadata_holds_optional_fields() {
        let md = sample_metadata();
        assert!(md.owner.is_none());
        assert!(md.rotation_due.is_none());
        assert!(md.expires_at.is_none());
        assert!(md.parent_key_id.is_none());
        assert!(md.attestation.is_none());
        assert!(!md.hardware_backed);
    }
}

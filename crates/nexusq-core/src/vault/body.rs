//! Vault body.
//!
//! The vault body is the CBOR-serialized structure that lives *inside*
//! the AEAD envelope of the vault file. It is encrypted with the vault
//! Key Encryption Key (KEK), which is derived from the user's password.
//!
//! Two layers of versioning exist:
//!
//! - The **file format version** lives in the vault header (see
//!   `docs/STORAGE.md` §4.1). It describes how the file itself is laid
//!   out: magic, version byte, KDF parameters, AEAD parameters.
//! - The **body schema version** lives in [`VaultMetadata::schema_version`].
//!   It describes the shape of the decrypted content. Because CBOR is
//!   self-describing, this version is only bumped on incompatible
//!   changes; adding an optional field does not require a bump.
//!
//! See `docs/STORAGE.md` §4.4.

use serde::{Deserialize, Serialize};

use super::{KeyRecord, Timestamp};
use crate::identity::Identity;
use crate::policy::PolicySet;

/// Current body schema version.
///
/// Bump this only when an existing field changes meaning or is removed.
/// Adding new optional fields does not require a bump.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Metadata about the vault itself.
///
/// This is distinct from [`crate::vault::KeyMetadata`], which describes
/// individual keys inside the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// Unique identifier for this vault.
    ///
    /// Format: `nqv_<hex>`. Generated at vault creation and never
    /// changed. Useful for correlating audit logs, backups and
    /// replicas of the same vault.
    pub vault_id: String,

    /// When the vault was first created.
    pub created_at: Timestamp,

    /// Free-form identifier of who or what created the vault.
    ///
    /// Will become a typed `IdentityId` when identities land (Fase 6).
    pub created_by: String,

    /// Optional human-readable label for the vault.
    ///
    /// Example: "alice-laptop", "production-signing". Not interpreted
    /// by the core; the CLI and UIs may display it.
    pub label: Option<String>,

    /// Schema version of the body.
    ///
    /// See the module documentation for when to bump this.
    pub schema_version: u32,
}

/// The decrypted content of a vault file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultBody {
    /// Metadata about the vault.
    pub metadata: VaultMetadata,

    /// All key records in the vault.
    ///
    /// Order is not significant; the vault looks up keys by
    /// [`crate::vault::KeyId`]. The vector is used for enumeration and
    /// serialization.
    pub keys: Vec<KeyRecord>,

    /// All identities in the vault.
    ///
    /// An identity references its keys by [`crate::vault::KeyId`]; it
    /// does not store key material itself. The field is optional on
    /// deserialization so vaults written before identities existed
    /// keep loading.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identities: Vec<Identity>,

    /// Access control policies for this vault.
    ///
    /// `None` means "no policy engine is active": every operation is
    /// allowed, matching the behavior of vaults created before the
    /// policy engine existed. `Some(set)` activates evaluation, and
    /// the set's default-deny rule takes over.
    ///
    /// The field is optional on deserialization for the same reason
    /// as `identities`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<PolicySet>,
}

impl VaultBody {
    /// Creates a new, empty body for a freshly created vault.
    #[must_use]
    pub fn new(metadata: VaultMetadata) -> Self {
        Self {
            metadata,
            keys: Vec::new(),
            identities: Vec::new(),
            policies: None,
        }
    }

    /// Returns the number of keys in the vault.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Finds a key by its id.
    #[must_use]
    pub fn find_key(&self, key_id: &super::KeyId) -> Option<&KeyRecord> {
        self.keys.iter().find(|r| r.key_id() == key_id)
    }

    /// Finds a key by its id, mutably.
    pub fn find_key_mut(&mut self, key_id: &super::KeyId) -> Option<&mut KeyRecord> {
        self.keys.iter_mut().find(|r| r.key_id() == key_id)
    }

    /// Returns the number of identities in the vault.
    #[must_use]
    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    /// Finds an identity by its id.
    #[must_use]
    pub fn find_identity(&self, id: &crate::identity::IdentityId) -> Option<&Identity> {
        self.identities.iter().find(|i| &i.id == id)
    }

    /// Finds an identity by its id, mutably.
    pub fn find_identity_mut(&mut self, id: &crate::identity::IdentityId) -> Option<&mut Identity> {
        self.identities.iter_mut().find(|i| &i.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;
    use crate::vault::{
        Algorithm, KeyId, KeyMetadata, KeyStatus, Origin, Purpose, WrappedKeyMaterial,
    };

    fn sample_metadata() -> VaultMetadata {
        VaultMetadata {
            vault_id: "nqv_aabbccddeeff00112233445566778899".to_string(),
            created_at: Timestamp::from_secs(1_700_000_000),
            created_by: "test".to_string(),
            label: Some("test-vault".to_string()),
            schema_version: CURRENT_SCHEMA_VERSION,
        }
    }

    fn sample_record() -> KeyRecord {
        let src = OsRandomSource::new();
        let key_id = KeyId::generate(&src, "ed25519").unwrap();
        KeyRecord::new(
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
            },
            WrappedKeyMaterial::Asymmetric(vec![0u8; 64]),
        )
    }

    #[test]
    fn new_body_is_empty() {
        let body = VaultBody::new(sample_metadata());
        assert_eq!(body.key_count(), 0);
        assert!(body.keys.is_empty());
    }

    #[test]
    fn find_key_returns_none_for_unknown_id() {
        let src = OsRandomSource::new();
        let body = VaultBody::new(sample_metadata());
        let other = KeyId::generate(&src, "ed25519").unwrap();
        assert!(body.find_key(&other).is_none());
    }

    #[test]
    fn find_key_returns_record_when_present() {
        let record = sample_record();
        let key_id = record.key_id().clone();
        let mut body = VaultBody::new(sample_metadata());
        body.keys.push(record);
        assert!(body.find_key(&key_id).is_some());
    }

    #[test]
    fn find_key_mut_allows_modification() {
        let record = sample_record();
        let key_id = record.key_id().clone();
        let mut body = VaultBody::new(sample_metadata());
        body.keys.push(record);

        let found = body.find_key_mut(&key_id).expect("present");
        found.metadata.status = KeyStatus::Retired;

        assert_eq!(body.find_key(&key_id).unwrap().status(), KeyStatus::Retired);
    }

    #[test]
    fn body_is_cloneable_and_eq() {
        let body = VaultBody::new(sample_metadata());
        let cloned = body.clone();
        assert_eq!(body, cloned);
    }

    #[test]
    fn current_schema_version_is_one() {
        assert_eq!(CURRENT_SCHEMA_VERSION, 1);
    }
}

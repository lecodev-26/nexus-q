//! Identity records.
//!
//! An [`Identity`] is a durable subject inside the vault: a name that
//! outlives the keys attached to it. It references key records by
//! [`KeyId`], it does not duplicate their material.
//!
//! See ADR 0004.

use serde::{Deserialize, Serialize};

use crate::vault::lifecycle::RevokeReason;
use crate::vault::{KeyId, Timestamp};

use super::id::IdentityId;
use super::status::IdentityStatus;

/// Metadata describing an identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMetadata {
    /// When the identity was created.
    pub created_at: Timestamp,

    /// Free-form identifier of who or what created the identity.
    ///
    /// Will become a typed `IdentityId` when a self-referential scheme
    /// is decided. For now it is an opaque string.
    pub created_by: String,

    /// Optional human-readable label.
    pub label: Option<String>,

    /// Current lifecycle status.
    pub status: IdentityStatus,

    /// Rotation generation, starting at 1 and bumped on each key
    /// rotation.
    pub version: u32,

    /// When the identity was revoked, if it was.
    pub revoked_at: Option<Timestamp>,

    /// Why the identity was revoked, if it was.
    pub revocation_reason: Option<RevokeReason>,
}

/// A durable NEXUS-Q identity.
///
/// The identity carries references to its keys but not the keys
/// themselves; those live in the vault as separate [`KeyRecord`]s.
///
/// [`KeyRecord`]: crate::vault::KeyRecord
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identifier. Never changes, even across key rotation.
    pub id: IdentityId,

    /// The key that signs documents on behalf of this identity.
    /// Always present.
    pub signing_key: KeyId,

    /// All signing keys ever assigned to this identity, in rotation order.
    /// This lets long-lived credentials bind to the exact historical key.
    #[serde(default)]
    pub signing_key_history: Vec<KeyId>,

    /// Optional key that decrypts messages sent to this identity.
    pub encryption_key: Option<KeyId>,

    /// Optional key used for KEM-based key agreement.
    pub key_agreement_key: Option<KeyId>,

    /// Metadata about the identity.
    pub metadata: IdentityMetadata,
}

impl Identity {
    /// Returns `true` if the identity is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.metadata.status == IdentityStatus::Active
    }

    /// Returns `true` if the identity has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.metadata.status == IdentityStatus::Revoked
    }

    /// Validates the internal consistency of the identity.
    ///
    /// Does not check that the referenced keys exist; that requires
    /// the vault and is the caller's responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityValidationError`] describing the first
    /// invariant that was violated.
    pub fn validate(&self) -> Result<(), IdentityValidationError> {
        if self.metadata.version == 0 {
            return Err(IdentityValidationError::VersionZero);
        }

        match (self.metadata.status, self.metadata.revoked_at) {
            (IdentityStatus::Revoked, None) => {
                return Err(IdentityValidationError::RevokedWithoutTimestamp);
            }
            (status, Some(_)) if status != IdentityStatus::Revoked => {
                return Err(IdentityValidationError::TimestampWithoutRevocation);
            }
            _ => {}
        }

        Ok(())
    }
}

/// Errors returned when an [`Identity`] fails validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityValidationError {
    /// The version field was zero.
    #[error("identity version must be at least 1")]
    VersionZero,

    /// The identity is revoked but carries no revocation timestamp.
    #[error("revoked identity is missing its revocation timestamp")]
    RevokedWithoutTimestamp,

    /// The identity is not revoked but carries a revocation timestamp.
    #[error("identity has a revocation timestamp but is not revoked")]
    TimestampWithoutRevocation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;
    use crate::vault::KeyId;

    fn sample_key_id(alg: &str) -> KeyId {
        let rng = OsRandomSource::new();
        KeyId::generate(&rng, alg).unwrap()
    }

    fn sample_identity() -> Identity {
        let rng = OsRandomSource::new();
        Identity {
            id: IdentityId::generate(&rng).unwrap(),
            signing_key: sample_key_id("ed25519"),
            signing_key_history: Vec::new(),
            encryption_key: Some(sample_key_id("aes256gcm")),
            key_agreement_key: Some(sample_key_id("mlkem768")),
            metadata: IdentityMetadata {
                created_at: Timestamp::from_secs(1_700_000_000),
                created_by: "test".to_string(),
                label: Some("alice".to_string()),
                status: IdentityStatus::Active,
                version: 1,
                revoked_at: None,
                revocation_reason: None,
            },
        }
    }

    #[test]
    fn sample_identity_is_active_and_valid() {
        let id = sample_identity();
        assert!(id.is_active());
        assert!(!id.is_revoked());
        assert!(id.validate().is_ok());
    }

    #[test]
    fn optional_keys_can_be_absent() {
        let mut id = sample_identity();
        id.encryption_key = None;
        id.key_agreement_key = None;
        assert!(id.validate().is_ok());
    }

    #[test]
    fn validate_rejects_version_zero() {
        let mut id = sample_identity();
        id.metadata.version = 0;
        assert!(matches!(
            id.validate(),
            Err(IdentityValidationError::VersionZero)
        ));
    }

    #[test]
    fn validate_rejects_revoked_without_timestamp() {
        let mut id = sample_identity();
        id.metadata.status = IdentityStatus::Revoked;
        id.metadata.revoked_at = None;
        assert!(matches!(
            id.validate(),
            Err(IdentityValidationError::RevokedWithoutTimestamp)
        ));
    }

    #[test]
    fn validate_rejects_timestamp_without_revocation() {
        let mut id = sample_identity();
        id.metadata.revoked_at = Some(Timestamp::from_secs(1_800_000_000));
        // status is still Active
        assert!(matches!(
            id.validate(),
            Err(IdentityValidationError::TimestampWithoutRevocation)
        ));
    }

    #[test]
    fn validate_accepts_revoked_with_timestamp_and_reason() {
        let mut id = sample_identity();
        id.metadata.status = IdentityStatus::Revoked;
        id.metadata.revoked_at = Some(Timestamp::from_secs(1_800_000_000));
        id.metadata.revocation_reason = Some(RevokeReason::Compromised);
        assert!(id.validate().is_ok());
        assert!(id.is_revoked());
    }

    #[test]
    fn identity_is_cloneable_and_eq() {
        let id = sample_identity();
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }
}

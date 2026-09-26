//! Key lifecycle operations.
//!
//! Types and reasons for the operations that move a key through its
//! [`KeyStatus`](super::KeyStatus) states: activation, rotation,
//! revocation and destruction.
//!
//! The operations themselves live on
//! [`Session`](super::Session); this module only provides the inputs
//! and the error vocabulary.
//!
//! See `docs/KEY_MANAGEMENT.md` §5 and §7-9.

use serde::{Deserialize, Serialize};

use super::KeyId;
use super::status::KeyStatus;

/// Why a key is being revoked.
///
/// Revocation is not deletion: the key material remains available so
/// data encrypted under it can still be recovered. What changes is
/// that the key is no longer trusted for new operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevokeReason {
    /// Suspected or confirmed compromise.
    Compromised,
    /// Superseded by another key outside the normal rotation flow.
    Superseded,
    /// The owner is no longer part of the organization.
    OwnerLeft,
    /// Any other reason; the string is a free-form explanation.
    Other(String),
}

impl RevokeReason {
    /// Returns a short, canonical tag for this reason.
    ///
    /// Used in audit records and diagnostics. Free-form details go in
    /// the `Other` variant's payload.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Compromised => "compromised",
            Self::Superseded => "superseded",
            Self::OwnerLeft => "owner_left",
            Self::Other(_) => "other",
        }
    }
}

/// Marker type that makes key destruction explicit at the call site.
///
/// Destroying a key is irreversible: data protected by it becomes
/// permanently unreadable. Requiring a value of this type forces the
/// caller to have consciously written `DestructionConfirmation::Explicit`
/// in the source, and prevents accidents where `destroy_key` is
/// invoked by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructionConfirmation {
    /// The caller has explicitly confirmed the destruction.
    Explicit,
}

/// Errors returned by lifecycle operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LifecycleError {
    /// No key with this id exists in the vault.
    #[error("key not found: {0}")]
    KeyNotFound(KeyId),

    /// The key exists but its status does not allow the operation.
    #[error("key {key_id} is in status {status}; operation requires {required}")]
    WrongStatus {
        /// The key in question.
        key_id: KeyId,
        /// Its current status.
        status: KeyStatus,
        /// The status the operation needed.
        required: &'static str,
    },

    /// The key is in a terminal state and cannot be transitioned.
    #[error("key {key_id} is {status}; no further transitions are allowed")]
    Terminal {
        /// The key in question.
        key_id: KeyId,
        /// Its terminal status.
        status: KeyStatus,
    },

    /// The internal state-machine rejected the transition.
    #[error("invalid key status transition: {0}")]
    Transition(#[from] super::status::StatusTransitionError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;

    fn sample_key_id() -> KeyId {
        let mut rng = OsRandomSource::new();
        KeyId::generate(&mut rng, "ed25519").unwrap()
    }

    #[test]
    fn revoke_reason_tags_are_stable() {
        assert_eq!(RevokeReason::Compromised.tag(), "compromised");
        assert_eq!(RevokeReason::Superseded.tag(), "superseded");
        assert_eq!(RevokeReason::OwnerLeft.tag(), "owner_left");
        assert_eq!(RevokeReason::Other("x".into()).tag(), "other");
    }

    #[test]
    fn revocation_reasons_roundtrip_cbor() {
        for reason in [
            RevokeReason::Compromised,
            RevokeReason::Superseded,
            RevokeReason::OwnerLeft,
            RevokeReason::Other("custom note".into()),
        ] {
            let bytes = crate::vault::serde_helpers::to_vec(&reason).unwrap();
            let back: RevokeReason = crate::vault::serde_helpers::from_slice(&bytes).unwrap();
            assert_eq!(back, reason);
        }
    }

    #[test]
    fn key_not_found_error_displays_key_id() {
        let id = sample_key_id();
        let err = LifecycleError::KeyNotFound(id.clone());
        assert!(err.to_string().contains(id.as_str()));
    }

    #[test]
    fn wrong_status_error_includes_required() {
        let id = sample_key_id();
        let err = LifecycleError::WrongStatus {
            key_id: id.clone(),
            status: KeyStatus::Generated,
            required: "ACTIVE",
        };
        let msg = err.to_string();
        assert!(msg.contains("generated"));
        assert!(msg.contains("ACTIVE"));
    }

    #[test]
    fn destruction_confirmation_is_copy() {
        let a = DestructionConfirmation::Explicit;
        let b = a;
        assert_eq!(a, b);
    }
}

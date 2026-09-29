//! Policy targets.
//!
//! A [`PolicyTarget`] says what a policy applies to. The evaluator
//! matches the target against the context of an operation: if the
//! target does not cover the operation's key or identity, the policy
//! is not consulted.
//!
//! Targets are deliberately coarse. Finer-grained rules (a specific
//! key, a specific identity) are expressed with the condition
//! variants, not with additional target kinds, so the evaluator has
//! one match site instead of two.
//!
//! See `docs/SECURITY_MODEL.md` §5.2.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;
use crate::vault::KeyId;

/// What a policy applies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyTarget {
    /// Every operation.
    All,
    /// Every operation that touches a key.
    AnyKey,
    /// Every operation that touches an identity.
    AnyIdentity,
    /// One specific key.
    Key(KeyId),
    /// One specific identity.
    Identity(IdentityId),
}

impl PolicyTarget {
    /// Returns `true` if this target covers `key_id`.
    #[must_use]
    pub fn matches_key(&self, key_id: &KeyId) -> bool {
        match self {
            Self::All | Self::AnyKey => true,
            Self::Key(id) => id == key_id,
            Self::AnyIdentity | Self::Identity(_) => false,
        }
    }

    /// Returns `true` if this target covers `identity_id`.
    #[must_use]
    pub fn matches_identity(&self, identity_id: &IdentityId) -> bool {
        match self {
            Self::All | Self::AnyIdentity => true,
            Self::Identity(id) => id == identity_id,
            Self::AnyKey | Self::Key(_) => false,
        }
    }

    /// Returns `true` if this target applies to operations that do
    /// not have a specific key or identity (e.g. `KeyCreate`).
    #[must_use]
    pub const fn matches_global(&self) -> bool {
        matches!(self, Self::All)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;

    fn key_id() -> KeyId {
        let source = OsRandomSource::new();
        KeyId::generate(&source, "ed25519").unwrap()
    }

    fn identity_id() -> IdentityId {
        let source = OsRandomSource::new();
        IdentityId::generate(&source).unwrap()
    }

    #[test]
    fn all_matches_everything() {
        let t = PolicyTarget::All;
        assert!(t.matches_key(&key_id()));
        assert!(t.matches_identity(&identity_id()));
        assert!(t.matches_global());
    }

    #[test]
    fn any_key_matches_any_key_but_not_identity() {
        let t = PolicyTarget::AnyKey;
        assert!(t.matches_key(&key_id()));
        assert!(!t.matches_identity(&identity_id()));
        assert!(!t.matches_global());
    }

    #[test]
    fn any_identity_matches_any_identity_but_not_key() {
        let t = PolicyTarget::AnyIdentity;
        assert!(t.matches_identity(&identity_id()));
        assert!(!t.matches_key(&key_id()));
        assert!(!t.matches_global());
    }

    #[test]
    fn specific_key_matches_only_itself() {
        let a = key_id();
        let b = key_id();
        let t = PolicyTarget::Key(a.clone());
        assert!(t.matches_key(&a));
        assert!(!t.matches_key(&b));
        assert!(!t.matches_identity(&identity_id()));
        assert!(!t.matches_global());
    }

    #[test]
    fn specific_identity_matches_only_itself() {
        let a = identity_id();
        let b = identity_id();
        let t = PolicyTarget::Identity(a.clone());
        assert!(t.matches_identity(&a));
        assert!(!t.matches_identity(&b));
        assert!(!t.matches_key(&key_id()));
        assert!(!t.matches_global());
    }

    #[test]
    fn targets_roundtrip_through_cbor() {
        for t in [
            PolicyTarget::All,
            PolicyTarget::AnyKey,
            PolicyTarget::AnyIdentity,
            PolicyTarget::Key(key_id()),
            PolicyTarget::Identity(identity_id()),
        ] {
            let bytes = crate::vault::to_vec(&t).unwrap();
            let back: PolicyTarget = crate::vault::from_slice(&bytes).unwrap();
            assert_eq!(back, t);
        }
    }
}

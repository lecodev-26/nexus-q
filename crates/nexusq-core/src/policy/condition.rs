//! Policy conditions.
//!
//! A policy may carry a list of conditions. Every condition must be
//! satisfied for the policy to apply. An empty list means the policy
//! applies unconditionally wherever its target matches.
//!
//! The set is closed: adding a new condition kind requires a new
//! match arm in the evaluator, so no condition can be silently
//! ignored.
//!
//! See `docs/SECURITY_MODEL.md` §5.2.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;
use crate::vault::{KeyId, KeyStatus};

use super::context::PolicyContext;

/// A requirement that must hold for a policy to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyCondition {
    /// The caller must be the given identity.
    ///
    /// If the operation has no caller, the condition fails.
    CallerIs(IdentityId),

    /// The operation must have an authenticated caller.
    ///
    /// Useful as a "no anonymous access" guard.
    RequiresCaller,

    /// The key's status must be one of these.
    ///
    /// If the operation has no key, the condition fails. Redundant
    /// with the vault's own state machine but useful for policies
    /// that only allow, say, `Active` keys during a particular
    /// window.
    KeyStatusIn(Vec<KeyStatus>),

    /// The operation must have happened at or after `not_before`.
    NotBefore(crate::vault::Timestamp),

    /// The operation must have happened strictly before `not_after`.
    NotAfter(crate::vault::Timestamp),

    /// The key must not be in the given list.
    KeyNotIn(Vec<KeyId>),

    /// The operation must have hardware attestation available.
    ///
    /// Fails when the context reports no attestation. On a software
    /// deployment this condition is never satisfied; policies that
    /// use it will refuse every matching operation until a hardware
    /// backend is in place.
    RequiresAttestation,
}

impl PolicyCondition {
    /// Returns `true` when this condition is satisfied by `context`.
    ///
    /// The method does not return an error for missing data: a
    /// condition that needs a caller when the context has none simply
    /// returns `false`. The evaluator treats an unsatisfied condition
    /// as "the policy does not apply", not as a failure.
    #[must_use]
    pub fn holds(&self, context: &PolicyContext) -> bool {
        match self {
            Self::CallerIs(expected) => context.caller.as_ref() == Some(expected),
            Self::RequiresCaller => context.caller.is_some(),
            Self::KeyStatusIn(allowed) => context
                .key_status
                .is_some_and(|status| allowed.contains(&status)),
            Self::NotBefore(threshold) => context.now >= *threshold,
            Self::NotAfter(threshold) => context.now < *threshold,
            Self::KeyNotIn(forbidden) => context
                .key_id
                .as_ref()
                .is_some_and(|id| !forbidden.contains(id)),
            Self::RequiresAttestation => context.hardware_attested,
        }
    }

    /// Returns a short, canonical tag for this condition.
    ///
    /// Used in audit records and diagnostics. The tag does not
    /// include the payload.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::CallerIs(_) => "caller_is",
            Self::RequiresCaller => "requires_caller",
            Self::KeyStatusIn(_) => "key_status_in",
            Self::NotBefore(_) => "not_before",
            Self::NotAfter(_) => "not_after",
            Self::KeyNotIn(_) => "key_not_in",
            Self::RequiresAttestation => "requires_attestation",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;
    use crate::vault::Timestamp;

    fn identity_id() -> IdentityId {
        let source = OsRandomSource::new();
        IdentityId::generate(&source).unwrap()
    }

    fn key_id() -> KeyId {
        let source = OsRandomSource::new();
        KeyId::generate(&source, "ed25519").unwrap()
    }

    #[test]
    fn condition_tags_are_stable() {
        assert_eq!(PolicyCondition::CallerIs(identity_id()).tag(), "caller_is");
        assert_eq!(PolicyCondition::RequiresCaller.tag(), "requires_caller");
        assert_eq!(
            PolicyCondition::KeyStatusIn(vec![KeyStatus::Active]).tag(),
            "key_status_in"
        );
        assert_eq!(
            PolicyCondition::NotBefore(Timestamp::from_secs(0)).tag(),
            "not_before"
        );
        assert_eq!(
            PolicyCondition::NotAfter(Timestamp::from_secs(0)).tag(),
            "not_after"
        );
        assert_eq!(PolicyCondition::KeyNotIn(vec![]).tag(), "key_not_in");
        assert_eq!(
            PolicyCondition::RequiresAttestation.tag(),
            "requires_attestation"
        );
    }

    // ----------------------------------------------------------------
    // holds() tests
    // ----------------------------------------------------------------

    fn ctx(operation: crate::policy::PolicyOperation) -> PolicyContext {
        PolicyContext::new(operation, Timestamp::from_secs(1_700_000_000))
    }

    #[test]
    fn requires_caller_holds_when_caller_present() {
        let id = identity_id();
        assert!(
            PolicyCondition::RequiresCaller
                .holds(&ctx(crate::policy::PolicyOperation::Sign).with_caller(id.clone()))
        );
        assert!(!PolicyCondition::RequiresCaller.holds(&ctx(crate::policy::PolicyOperation::Sign)));
    }

    #[test]
    fn caller_is_holds_only_for_the_right_caller() {
        let alice = identity_id();
        let bob = identity_id();
        let c_alice = ctx(crate::policy::PolicyOperation::Sign).with_caller(alice.clone());
        let c_bob = ctx(crate::policy::PolicyOperation::Sign).with_caller(bob);

        assert!(PolicyCondition::CallerIs(alice.clone()).holds(&c_alice));
        assert!(!PolicyCondition::CallerIs(alice).holds(&c_bob));
    }

    #[test]
    fn caller_is_fails_when_no_caller() {
        let id = identity_id();
        let c = ctx(crate::policy::PolicyOperation::Sign);
        assert!(!PolicyCondition::CallerIs(id).holds(&c));
    }

    #[test]
    fn key_status_in_matches_when_status_allowed() {
        let id = key_id();
        let c = ctx(crate::policy::PolicyOperation::Sign).with_key(id, KeyStatus::Active);
        assert!(PolicyCondition::KeyStatusIn(vec![KeyStatus::Active]).holds(&c));
        assert!(!PolicyCondition::KeyStatusIn(vec![KeyStatus::Revoked]).holds(&c));
    }

    #[test]
    fn key_status_in_fails_when_no_key() {
        let c = ctx(crate::policy::PolicyOperation::KeyCreate);
        assert!(!PolicyCondition::KeyStatusIn(vec![KeyStatus::Active]).holds(&c));
    }

    #[test]
    fn not_before_and_not_after_bound_the_window() {
        let c = ctx(crate::policy::PolicyOperation::Sign);
        let before = Timestamp::from_secs(1_699_999_999);
        let after = Timestamp::from_secs(1_700_000_001);

        assert!(PolicyCondition::NotBefore(before).holds(&c));
        assert!(!PolicyCondition::NotBefore(after).holds(&c));
        assert!(PolicyCondition::NotAfter(after).holds(&c));
        assert!(!PolicyCondition::NotAfter(before).holds(&c));
    }

    #[test]
    fn key_not_in_holds_when_key_is_allowed() {
        let a = key_id();
        let b = key_id();
        let c = ctx(crate::policy::PolicyOperation::Sign).with_key(a.clone(), KeyStatus::Active);

        assert!(PolicyCondition::KeyNotIn(vec![b]).holds(&c));
        assert!(!PolicyCondition::KeyNotIn(vec![a]).holds(&c));
    }

    #[test]
    fn requires_attestation_holds_only_when_attested() {
        let with = ctx(crate::policy::PolicyOperation::Sign).with_attestation();
        let without = ctx(crate::policy::PolicyOperation::Sign);

        assert!(PolicyCondition::RequiresAttestation.holds(&with));
        assert!(!PolicyCondition::RequiresAttestation.holds(&without));
    }

    #[test]
    fn conditions_roundtrip_through_cbor() {
        let cases = vec![
            PolicyCondition::CallerIs(identity_id()),
            PolicyCondition::RequiresCaller,
            PolicyCondition::KeyStatusIn(vec![KeyStatus::Active, KeyStatus::Rotating]),
            PolicyCondition::NotBefore(Timestamp::from_secs(1_700_000_000)),
            PolicyCondition::NotAfter(Timestamp::from_secs(1_800_000_000)),
            PolicyCondition::KeyNotIn(vec![key_id()]),
            PolicyCondition::RequiresAttestation,
        ];

        for case in cases {
            let bytes = crate::vault::to_vec(&case).unwrap();
            let back: PolicyCondition = crate::vault::from_slice(&bytes).unwrap();
            assert_eq!(back, case);
        }
    }
}

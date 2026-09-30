//! Policy set and evaluation.
//!
//! A [`PolicySet`] holds a list of [`Policy`] rules. Evaluation is
//! deterministic and fail-closed:
//!
//! 1. Rules are consulted in order.
//! 2. A rule applies when (a) the context's operation is one of the
//!    rule's operations, (b) the rule's target matches the context,
//!    and (c) every condition holds.
//! 3. The first applying deny wins and is returned immediately.
//! 4. Applying allows are remembered; the first one is returned if no
//!    deny is found.
//! 5. If no rule applies, the decision is `NoDecision`. Callers treat
//!    that as a refusal, following the "deny by default" rule from
//!    `docs/SECURITY_MODEL.md` §5.2.
//!
//! Point 3 is what makes the engine fail-closed: no amount of later
//! allows can override an earlier deny, and a deny can be placed at
//! the top of the list to act as a guard.
//!
//! See `docs/SECURITY_MODEL.md` §5.2.

use serde::{Deserialize, Serialize};

use super::context::PolicyContext;
use super::decision::PolicyDecision;
use super::rule::{Policy, PolicyEffect};
use super::target::PolicyTarget;

/// An ordered list of rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySet {
    policies: Vec<Policy>,
}

impl PolicySet {
    /// Creates an empty set.
    ///
    /// An empty set denies everything: evaluation returns
    /// [`PolicyDecision::NoDecision`], which callers treat as a
    /// refusal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a rule to the end of the list.
    pub fn add(&mut self, policy: Policy) -> &mut Self {
        self.policies.push(policy);
        self
    }

    /// Returns the rules in order.
    #[must_use]
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// Returns the number of rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Returns `true` if the set has no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Evaluates the set against `context`.
    ///
    /// # Errors
    ///
    /// This function does not currently fail. It returns a `Result`
    /// so that a future version can surface problems that are not
    /// expressible as a decision (for example, an invalid rule
    /// reference).
    pub fn evaluate(
        &self,
        context: &PolicyContext,
    ) -> Result<PolicyDecision, super::error::PolicyError> {
        let mut first_allow: Option<usize> = None;

        for (index, policy) in self.policies.iter().enumerate() {
            if !policy_applies(policy, context) {
                continue;
            }

            match &policy.effect {
                PolicyEffect::Deny { reason } => {
                    // First deny wins and is returned immediately.
                    return Ok(PolicyDecision::Deny {
                        policy_index: index,
                        reason: reason.clone(),
                    });
                }
                PolicyEffect::Allow => {
                    // Remember the first allow but keep scanning for
                    // a later deny.
                    if first_allow.is_none() {
                        first_allow = Some(index);
                    }
                }
            }
        }

        Ok(match first_allow {
            Some(policy_index) => PolicyDecision::Allow { policy_index },
            None => PolicyDecision::NoDecision,
        })
    }
}

/// Returns `true` if `policy` covers `context`.
fn policy_applies(policy: &Policy, context: &PolicyContext) -> bool {
    if !policy.operations.contains(&context.operation) {
        return false;
    }
    if !target_matches(&policy.target, context) {
        return false;
    }
    policy.conditions.iter().all(|c| c.holds(context))
}

/// Returns `true` if `target` covers the context's key or identity.
///
/// A target only matches when the context carries the corresponding
/// element. `AnyKey` will not match an operation with no key, and
/// `AnyIdentity` will not match an operation with no identity.
fn target_matches(target: &PolicyTarget, context: &PolicyContext) -> bool {
    match target {
        PolicyTarget::All => true,
        PolicyTarget::AnyKey => context.key_id.is_some(),
        PolicyTarget::AnyIdentity => context.identity_id.is_some(),
        PolicyTarget::Key(id) => context.key_id.as_ref() == Some(id),
        PolicyTarget::Identity(id) => context.identity_id.as_ref() == Some(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;
    use crate::identity::IdentityId;
    use crate::policy::PolicyOperation;
    use crate::policy::condition::PolicyCondition;
    use crate::vault::{KeyId, KeyStatus, Timestamp};

    fn key_id() -> KeyId {
        let source = OsRandomSource::new();
        KeyId::generate(&source, "ed25519").unwrap()
    }

    fn identity_id() -> IdentityId {
        let source = OsRandomSource::new();
        IdentityId::generate(&source).unwrap()
    }

    fn now() -> Timestamp {
        Timestamp::from_secs(1_700_000_000)
    }

    fn allow(label: &str, op: PolicyOperation, target: PolicyTarget) -> Policy {
        Policy::new(label, PolicyEffect::Allow)
            .for_operations(vec![op])
            .on(target)
    }

    fn deny(label: &str, op: PolicyOperation, target: PolicyTarget) -> Policy {
        Policy::new(
            label,
            PolicyEffect::Deny {
                reason: "test deny".into(),
            },
        )
        .for_operations(vec![op])
        .on(target)
    }

    // ----------------------------------------------------------------
    // Basic semantics
    // ----------------------------------------------------------------

    #[test]
    fn empty_set_returns_no_decision() {
        let set = PolicySet::new();
        let ctx = PolicyContext::new(PolicyOperation::Sign, now());
        assert!(set.evaluate(&ctx).unwrap().is_no_decision());
    }

    #[test]
    fn single_allow_matching_operation_returns_allow() {
        let mut set = PolicySet::new();
        set.add(allow("a", PolicyOperation::Sign, PolicyTarget::All));

        let ctx = PolicyContext::new(PolicyOperation::Sign, now());
        let decision = set.evaluate(&ctx).unwrap();
        assert!(decision.is_allow());
    }

    #[test]
    fn single_allow_matching_different_operation_returns_no_decision() {
        let mut set = PolicySet::new();
        set.add(allow("a", PolicyOperation::Sign, PolicyTarget::All));

        let ctx = PolicyContext::new(PolicyOperation::KeyCreate, now());
        assert!(set.evaluate(&ctx).unwrap().is_no_decision());
    }

    #[test]
    fn single_deny_matching_returns_deny() {
        let mut set = PolicySet::new();
        set.add(deny("d", PolicyOperation::Sign, PolicyTarget::All));

        let ctx = PolicyContext::new(PolicyOperation::Sign, now());
        let decision = set.evaluate(&ctx).unwrap();
        assert!(decision.is_deny());
    }

    #[test]
    fn deny_wins_over_earlier_allow() {
        let mut set = PolicySet::new();
        set.add(allow("a", PolicyOperation::Sign, PolicyTarget::All));
        set.add(deny("d", PolicyOperation::Sign, PolicyTarget::All));

        let ctx = PolicyContext::new(PolicyOperation::Sign, now());
        assert!(set.evaluate(&ctx).unwrap().is_deny());
    }

    #[test]
    fn deny_wins_over_later_allow() {
        let mut set = PolicySet::new();
        set.add(deny("d", PolicyOperation::Sign, PolicyTarget::All));
        set.add(allow("a", PolicyOperation::Sign, PolicyTarget::All));

        let ctx = PolicyContext::new(PolicyOperation::Sign, now());
        assert!(set.evaluate(&ctx).unwrap().is_deny());
    }

    #[test]
    fn first_allow_is_reported() {
        let mut set = PolicySet::new();
        set.add(allow("first", PolicyOperation::Sign, PolicyTarget::All));
        set.add(allow("second", PolicyOperation::Sign, PolicyTarget::All));

        let ctx = PolicyContext::new(PolicyOperation::Sign, now());
        match set.evaluate(&ctx).unwrap() {
            PolicyDecision::Allow { policy_index } => assert_eq!(policy_index, 0),
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn first_deny_is_reported() {
        let mut set = PolicySet::new();
        set.add(allow("a", PolicyOperation::Sign, PolicyTarget::All));
        set.add(deny("first-deny", PolicyOperation::Sign, PolicyTarget::All));
        set.add(deny(
            "second-deny",
            PolicyOperation::Sign,
            PolicyTarget::All,
        ));

        let ctx = PolicyContext::new(PolicyOperation::Sign, now());
        match set.evaluate(&ctx).unwrap() {
            PolicyDecision::Deny { policy_index, .. } => assert_eq!(policy_index, 1),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    // ----------------------------------------------------------------
    // Target matching
    // ----------------------------------------------------------------

    #[test]
    fn any_key_does_not_match_operation_without_a_key() {
        let mut set = PolicySet::new();
        set.add(allow("a", PolicyOperation::Sign, PolicyTarget::AnyKey));

        let ctx_without = PolicyContext::new(PolicyOperation::Sign, now());
        assert!(set.evaluate(&ctx_without).unwrap().is_no_decision());

        let ctx_with =
            PolicyContext::new(PolicyOperation::Sign, now()).with_key(key_id(), KeyStatus::Active);
        assert!(set.evaluate(&ctx_with).unwrap().is_allow());
    }

    #[test]
    fn specific_key_matches_only_itself() {
        let a = key_id();
        let b = key_id();

        let mut set = PolicySet::new();
        set.add(allow(
            "a",
            PolicyOperation::Sign,
            PolicyTarget::Key(a.clone()),
        ));

        let ctx_a = PolicyContext::new(PolicyOperation::Sign, now()).with_key(a, KeyStatus::Active);
        let ctx_b = PolicyContext::new(PolicyOperation::Sign, now()).with_key(b, KeyStatus::Active);

        assert!(set.evaluate(&ctx_a).unwrap().is_allow());
        assert!(set.evaluate(&ctx_b).unwrap().is_no_decision());
    }

    #[test]
    fn all_target_matches_operations_without_key_or_identity() {
        let mut set = PolicySet::new();
        set.add(allow("a", PolicyOperation::KeyCreate, PolicyTarget::All));

        let ctx = PolicyContext::new(PolicyOperation::KeyCreate, now());
        assert!(set.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn any_identity_does_not_match_operation_without_identity() {
        let mut set = PolicySet::new();
        set.add(allow(
            "a",
            PolicyOperation::IdentitySign,
            PolicyTarget::AnyIdentity,
        ));

        let ctx_without = PolicyContext::new(PolicyOperation::IdentitySign, now());
        assert!(set.evaluate(&ctx_without).unwrap().is_no_decision());

        let ctx_with =
            PolicyContext::new(PolicyOperation::IdentitySign, now()).with_identity(identity_id());
        assert!(set.evaluate(&ctx_with).unwrap().is_allow());
    }

    // ----------------------------------------------------------------
    // Condition handling
    // ----------------------------------------------------------------

    #[test]
    fn policy_with_unsatisfied_condition_does_not_apply() {
        let mut set = PolicySet::new();
        let mut p = allow("a", PolicyOperation::Sign, PolicyTarget::All);
        p = p.and_condition(PolicyCondition::RequiresCaller);
        set.add(p);

        let ctx_no_caller = PolicyContext::new(PolicyOperation::Sign, now());
        assert!(set.evaluate(&ctx_no_caller).unwrap().is_no_decision());

        let ctx_with_caller =
            PolicyContext::new(PolicyOperation::Sign, now()).with_caller(identity_id());
        assert!(set.evaluate(&ctx_with_caller).unwrap().is_allow());
    }

    #[test]
    fn all_conditions_must_hold() {
        let mut set = PolicySet::new();
        let p = allow("a", PolicyOperation::Sign, PolicyTarget::All)
            .and_condition(PolicyCondition::RequiresCaller)
            .and_condition(PolicyCondition::RequiresAttestation);
        set.add(p);

        // Has caller but no attestation → condition 2 fails.
        let ctx = PolicyContext::new(PolicyOperation::Sign, now()).with_caller(identity_id());
        assert!(set.evaluate(&ctx).unwrap().is_no_decision());

        // Has caller and attestation → both conditions hold.
        let ctx = PolicyContext::new(PolicyOperation::Sign, now())
            .with_caller(identity_id())
            .with_attestation();
        assert!(set.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn deny_with_condition_only_fires_when_condition_holds() {
        let mut set = PolicySet::new();
        set.add(allow("a", PolicyOperation::Sign, PolicyTarget::All));
        set.add(
            deny("d", PolicyOperation::Sign, PolicyTarget::All)
                .and_condition(PolicyCondition::RequiresAttestation),
        );

        // No attestation → deny does not apply → allow stands.
        let ctx_no_att = PolicyContext::new(PolicyOperation::Sign, now());
        assert!(set.evaluate(&ctx_no_att).unwrap().is_allow());

        // Attestation on → deny applies.
        let ctx_att = PolicyContext::new(PolicyOperation::Sign, now()).with_attestation();
        assert!(set.evaluate(&ctx_att).unwrap().is_deny());
    }

    // ----------------------------------------------------------------
    // Set helpers
    // ----------------------------------------------------------------

    #[test]
    fn len_and_is_empty_are_consistent() {
        let mut set = PolicySet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        set.add(allow("a", PolicyOperation::Sign, PolicyTarget::All));
        assert!(!set.is_empty());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn policies_returns_slice_in_order() {
        let mut set = PolicySet::new();
        set.add(allow("first", PolicyOperation::Sign, PolicyTarget::All));
        set.add(allow("second", PolicyOperation::Verify, PolicyTarget::All));

        let labels: Vec<_> = set.policies().iter().map(|p| p.label.as_str()).collect();
        assert_eq!(labels, vec!["first", "second"]);
    }

    #[test]
    fn policy_set_roundtrips_through_cbor() {
        let mut set = PolicySet::new();
        set.add(allow("a", PolicyOperation::Sign, PolicyTarget::All));
        set.add(
            deny("d", PolicyOperation::Encrypt, PolicyTarget::AnyKey)
                .and_condition(PolicyCondition::RequiresCaller),
        );

        let bytes = crate::vault::to_vec(&set).unwrap();
        let back: PolicySet = crate::vault::from_slice(&bytes).unwrap();
        assert_eq!(back, set);
    }
}

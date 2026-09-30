//! A single policy rule.
//!
//! A [`Policy`] says: for these operations, against this target, under
//! these conditions, the effect is allow or deny. The evaluator
//! consults rules in order and applies the first matching deny,
//! remembering any matching allow.
//!
//! Rules are deliberately coarse. A single rule covers a set of
//! operations and a single target; the caller decides how to break a
//! policy file down into rules. Splitting into more rules is cheap
//! (the evaluator is O(n) in the number of rules) and makes each rule
//! easier to reason about.
//!
//! See `docs/SECURITY_MODEL.md` §5.2.

use serde::{Deserialize, Serialize};

use super::condition::PolicyCondition;
use super::operation::PolicyOperation;
use super::target::PolicyTarget;

/// What a matching policy does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEffect {
    /// Allow the operation.
    Allow,
    /// Deny the operation with the given reason.
    Deny {
        /// Human-readable reason, surfaced in audit records.
        reason: String,
    },
}

impl PolicyEffect {
    /// Returns `true` for [`PolicyEffect::Allow`].
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` for [`PolicyEffect::Deny`].
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns the reason for a deny, or `None` for an allow.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Deny { reason } => Some(reason),
        }
    }
}

/// A single rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Human-readable label for logs and audit records.
    ///
    /// Never used for matching. Two policies may share a label.
    pub label: String,

    /// Operations this rule covers.
    ///
    /// The rule applies only when the context's operation is one of
    /// these.
    pub operations: Vec<PolicyOperation>,

    /// Target this rule covers.
    pub target: PolicyTarget,

    /// Conditions that must all hold for the rule to apply.
    ///
    /// An empty list means "no extra conditions"; the rule applies
    /// wherever its operation and target match.
    pub conditions: Vec<PolicyCondition>,

    /// Effect when the rule applies.
    pub effect: PolicyEffect,
}

impl Policy {
    /// Creates a rule with the given label and effect.
    ///
    /// Operations, target and conditions start empty; use
    /// [`Policy::for_operations`], [`Policy::on`], and
    /// [`Policy::when`] to fill them.
    #[must_use]
    pub fn new(label: impl Into<String>, effect: PolicyEffect) -> Self {
        Self {
            label: label.into(),
            operations: Vec::new(),
            target: PolicyTarget::All,
            conditions: Vec::new(),
            effect,
        }
    }

    /// Sets the covered operations.
    #[must_use]
    pub fn for_operations(mut self, operations: Vec<PolicyOperation>) -> Self {
        self.operations = operations;
        self
    }

    /// Sets the target.
    #[must_use]
    pub fn on(mut self, target: PolicyTarget) -> Self {
        self.target = target;
        self
    }

    /// Sets the conditions.
    #[must_use]
    pub fn when(mut self, conditions: Vec<PolicyCondition>) -> Self {
        self.conditions = conditions;
        self
    }

    /// Adds a single condition to the existing list.
    #[must_use]
    pub fn and_condition(mut self, condition: PolicyCondition) -> Self {
        self.conditions.push(condition);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyOperation;

    #[test]
    fn new_policy_has_expected_defaults() {
        let p = Policy::new("test", PolicyEffect::Allow);
        assert_eq!(p.label, "test");
        assert!(p.operations.is_empty());
        assert_eq!(p.target, PolicyTarget::All);
        assert!(p.conditions.is_empty());
        assert!(p.effect.is_allow());
    }

    #[test]
    fn builder_fills_all_fields() {
        let p = Policy::new("sign-allow", PolicyEffect::Allow)
            .for_operations(vec![PolicyOperation::Sign, PolicyOperation::Verify])
            .on(PolicyTarget::AnyKey)
            .when(vec![PolicyCondition::RequiresCaller]);

        assert_eq!(p.operations.len(), 2);
        assert_eq!(p.target, PolicyTarget::AnyKey);
        assert_eq!(p.conditions.len(), 1);
    }

    #[test]
    fn and_condition_appends() {
        let p = Policy::new("x", PolicyEffect::Allow)
            .and_condition(PolicyCondition::RequiresCaller)
            .and_condition(PolicyCondition::RequiresAttestation);

        assert_eq!(p.conditions.len(), 2);
    }

    #[test]
    fn effect_helpers_are_consistent() {
        let allow = PolicyEffect::Allow;
        assert!(allow.is_allow());
        assert!(!allow.is_deny());
        assert!(allow.reason().is_none());

        let deny = PolicyEffect::Deny {
            reason: "nope".into(),
        };
        assert!(deny.is_deny());
        assert!(!deny.is_allow());
        assert_eq!(deny.reason(), Some("nope"));
    }

    #[test]
    fn policy_roundtrips_through_cbor() {
        let p = Policy::new(
            "test",
            PolicyEffect::Deny {
                reason: "no thanks".into(),
            },
        )
        .for_operations(vec![PolicyOperation::Sign])
        .on(PolicyTarget::AnyKey)
        .when(vec![PolicyCondition::RequiresCaller]);

        let bytes = crate::vault::to_vec(&p).unwrap();
        let back: Policy = crate::vault::from_slice(&bytes).unwrap();
        assert_eq!(back, p);
    }
}

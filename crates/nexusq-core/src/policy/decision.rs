//! Policy decisions.
//!
//! The result of evaluating a [`PolicySet`](super::PolicySet) against a
//! [`PolicyContext`](super::PolicyContext) is one of three values:
//!
//! - `Allow`: at least one matching policy allowed the operation and
//!   no matching policy denied it.
//! - `Deny`: at least one matching policy denied the operation.
//! - `NoDecision`: no policy matched. By default this is treated as a
//!   denial by the session, following the "deny by default" rule from
//!   `docs/SECURITY_MODEL.md` §5.2.
//!
//! Distinguishing `Deny` from `NoDecision` matters for audit and
//! diagnostics: a `Deny` says a rule actively refused, while
//! `NoDecision` says nobody thought to allow it.

use serde::{Deserialize, Serialize};

/// The result of evaluating policies against a context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// An explicit rule allowed the operation.
    Allow {
        /// Index of the policy that allowed it, for audit.
        policy_index: usize,
    },

    /// An explicit rule denied the operation.
    Deny {
        /// Index of the policy that denied it, for audit.
        policy_index: usize,
        /// Reason supplied by the policy, for logs.
        reason: String,
    },

    /// No policy matched the context.
    NoDecision,
}

impl PolicyDecision {
    /// Returns `true` only for [`PolicyDecision::Allow`].
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Returns `true` only for [`PolicyDecision::Deny`].
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns `true` for [`PolicyDecision::NoDecision`].
    #[must_use]
    pub const fn is_no_decision(&self) -> bool {
        matches!(self, Self::NoDecision)
    }

    /// Returns `true` when the session should proceed.
    ///
    /// Only [`PolicyDecision::Allow`] qualifies. `NoDecision` is a
    /// refusal at the call site.
    #[must_use]
    pub const fn permits(&self) -> bool {
        self.is_allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_is_allow() {
        let d = PolicyDecision::Allow { policy_index: 0 };
        assert!(d.is_allow());
        assert!(!d.is_deny());
        assert!(!d.is_no_decision());
        assert!(d.permits());
    }

    #[test]
    fn deny_is_deny() {
        let d = PolicyDecision::Deny {
            policy_index: 1,
            reason: "no".into(),
        };
        assert!(d.is_deny());
        assert!(!d.is_allow());
        assert!(!d.is_no_decision());
        assert!(!d.permits());
    }

    #[test]
    fn no_decision_does_not_permit() {
        let d = PolicyDecision::NoDecision;
        assert!(d.is_no_decision());
        assert!(!d.is_allow());
        assert!(!d.is_deny());
        assert!(!d.permits());
    }

    #[test]
    fn decisions_roundtrip_through_cbor() {
        for d in [
            PolicyDecision::Allow { policy_index: 3 },
            PolicyDecision::Deny {
                policy_index: 7,
                reason: "test".into(),
            },
            PolicyDecision::NoDecision,
        ] {
            let bytes = crate::vault::to_vec(&d).unwrap();
            let back: PolicyDecision = crate::vault::from_slice(&bytes).unwrap();
            assert_eq!(back, d);
        }
    }
}

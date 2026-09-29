//! Policy errors.
//!
//! Errors raised while defining or evaluating policies. An evaluator
//! that cannot decide returns one of these; a session that refuses an
//! operation returns [`PolicyError::Denied`] with the decision that
//! produced the refusal.

use thiserror::Error;

use crate::identity::IdentityId;
use crate::vault::KeyId;

use super::decision::PolicyDecision;

/// Errors returned by policy definition and evaluation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// A policy set could not be serialized or deserialized.
    #[error("policy serialization error")]
    Serialization,

    /// The evaluator was asked to decide without enough context.
    ///
    /// For example, a policy targets a key but the context has none.
    #[error("policy context is missing data needed for evaluation")]
    IncompleteContext,

    /// The operation was refused.
    ///
    /// Carries the decision so the caller can see whether it was an
    /// explicit denial or the absence of any rule.
    #[error("operation denied by policy")]
    Denied(PolicyDecision),

    /// A specific key is required by the operation but absent.
    #[error("operation requires a key but none was provided")]
    KeyRequired,

    /// A specific identity is required by the operation but absent.
    #[error("operation requires an identity but none was provided")]
    IdentityRequired,

    /// A key id was referenced but the vault does not know it.
    #[error("unknown key: {0}")]
    UnknownKey(KeyId),

    /// An identity id was referenced but the vault does not know it.
    #[error("unknown identity: {0}")]
    UnknownIdentity(IdentityId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;

    #[test]
    fn error_messages_are_stable() {
        assert_eq!(
            PolicyError::Serialization.to_string(),
            "policy serialization error"
        );
        assert_eq!(
            PolicyError::IncompleteContext.to_string(),
            "policy context is missing data needed for evaluation"
        );
        assert_eq!(
            PolicyError::Denied(PolicyDecision::NoDecision).to_string(),
            "operation denied by policy"
        );
        assert_eq!(
            PolicyError::KeyRequired.to_string(),
            "operation requires a key but none was provided"
        );
        assert_eq!(
            PolicyError::IdentityRequired.to_string(),
            "operation requires an identity but none was provided"
        );
    }

    #[test]
    fn unknown_key_error_carries_the_id() {
        let source = OsRandomSource::new();
        let id = KeyId::generate(&source, "ed25519").unwrap();
        let err = PolicyError::UnknownKey(id.clone());
        assert!(err.to_string().contains(id.as_str()));
    }

    #[test]
    fn unknown_identity_error_carries_the_id() {
        let source = OsRandomSource::new();
        let id = IdentityId::generate(&source).unwrap();
        let err = PolicyError::UnknownIdentity(id.clone());
        assert!(err.to_string().contains(id.as_str()));
    }
}

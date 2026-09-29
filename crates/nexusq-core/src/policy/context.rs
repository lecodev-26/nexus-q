//! Policy evaluation context.
//!
//! The [`PolicyContext`] carries everything the evaluator needs to
//! decide whether a policy applies and whether its conditions hold:
//! the operation, the caller (if any), the key or identity being
//! touched, and the current time.
//!
//! A context is built by the caller of the policy engine, not by the
//! engine itself. This keeps the engine free of hidden state and
//! makes evaluation trivially testable: construct a context, call
//! `evaluate`, inspect the decision.
//!
//! See `docs/SECURITY_MODEL.md` §5.2.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;
use crate::vault::{KeyId, KeyStatus, Timestamp};

use super::operation::PolicyOperation;

/// The situation in which a policy is evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContext {
    /// The operation being attempted.
    pub operation: PolicyOperation,

    /// The caller's identity, if authenticated.
    ///
    /// Operations initiated by the vault itself (for example, an
    /// automatic rotation) leave this as `None`; policies that require
    /// a caller will deny them.
    pub caller: Option<IdentityId>,

    /// The key being used, if the operation touches one.
    pub key_id: Option<KeyId>,

    /// The current status of `key_id`, if available.
    ///
    /// Filled by the session before evaluation when it can look the
    /// key up. Policies that do not care leave the field unused.
    pub key_status: Option<KeyStatus>,

    /// The identity being used, if the operation touches one.
    pub identity_id: Option<IdentityId>,

    /// The current time.
    pub now: Timestamp,

    /// Whether hardware attestation is available for this operation.
    ///
    /// A software backend always reports `false`. A hardware-backed
    /// session reports `true` when its attestation provider has
    /// produced a fresh report.
    pub hardware_attested: bool,
}

impl PolicyContext {
    /// Creates a context for the given operation at `now`.
    ///
    /// All optional fields start as `None` and `hardware_attested` as
    /// `false`.
    #[must_use]
    pub const fn new(operation: PolicyOperation, now: Timestamp) -> Self {
        Self {
            operation,
            caller: None,
            key_id: None,
            key_status: None,
            identity_id: None,
            now,
            hardware_attested: false,
        }
    }

    /// Sets the caller.
    #[must_use]
    pub fn with_caller(mut self, caller: IdentityId) -> Self {
        self.caller = Some(caller);
        self
    }

    /// Sets the key being used.
    #[must_use]
    pub fn with_key(mut self, key_id: KeyId, status: KeyStatus) -> Self {
        self.key_id = Some(key_id);
        self.key_status = Some(status);
        self
    }

    /// Sets the identity being used.
    #[must_use]
    pub fn with_identity(mut self, identity_id: IdentityId) -> Self {
        self.identity_id = Some(identity_id);
        self
    }

    /// Marks hardware attestation as available.
    #[must_use]
    pub const fn with_attestation(mut self) -> Self {
        self.hardware_attested = true;
        self
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

    fn now() -> Timestamp {
        Timestamp::from_secs(1_700_000_000)
    }

    #[test]
    fn new_context_has_all_optionals_empty() {
        let ctx = PolicyContext::new(PolicyOperation::KeyCreate, now());
        assert!(ctx.caller.is_none());
        assert!(ctx.key_id.is_none());
        assert!(ctx.key_status.is_none());
        assert!(ctx.identity_id.is_none());
        assert!(!ctx.hardware_attested);
    }

    #[test]
    fn with_caller_sets_the_caller() {
        let caller = identity_id();
        let ctx = PolicyContext::new(PolicyOperation::Sign, now()).with_caller(caller.clone());
        assert_eq!(ctx.caller, Some(caller));
    }

    #[test]
    fn with_key_sets_id_and_status() {
        let id = key_id();
        let ctx = PolicyContext::new(PolicyOperation::Sign, now())
            .with_key(id.clone(), KeyStatus::Active);
        assert_eq!(ctx.key_id, Some(id));
        assert_eq!(ctx.key_status, Some(KeyStatus::Active));
    }

    #[test]
    fn with_identity_sets_the_identity() {
        let id = identity_id();
        let ctx =
            PolicyContext::new(PolicyOperation::IdentitySign, now()).with_identity(id.clone());
        assert_eq!(ctx.identity_id, Some(id));
    }

    #[test]
    fn with_attestation_flips_the_flag() {
        let ctx = PolicyContext::new(PolicyOperation::Sign, now()).with_attestation();
        assert!(ctx.hardware_attested);
    }

    #[test]
    fn builders_compose() {
        let caller = identity_id();
        let key = key_id();
        let ctx = PolicyContext::new(PolicyOperation::Sign, now())
            .with_caller(caller.clone())
            .with_key(key.clone(), KeyStatus::Active)
            .with_attestation();

        assert_eq!(ctx.caller, Some(caller));
        assert_eq!(ctx.key_id, Some(key));
        assert_eq!(ctx.key_status, Some(KeyStatus::Active));
        assert!(ctx.hardware_attested);
    }

    #[test]
    fn context_roundtrips_through_cbor() {
        let ctx = PolicyContext::new(PolicyOperation::Sign, now())
            .with_caller(identity_id())
            .with_key(key_id(), KeyStatus::Active)
            .with_attestation();
        let bytes = crate::vault::to_vec(&ctx).unwrap();
        let back: PolicyContext = crate::vault::from_slice(&bytes).unwrap();
        assert_eq!(back, ctx);
    }
}

//! Property-based security invariants for the policy evaluator.
//!
//! Reproduce a failure with the seed and case printed by proptest, or set
//! `PROPTEST_RNG_SEED` and `PROPTEST_CASES` to replay/expand a run. Persisted
//! counterexamples are stored in proptest's `proptest-regressions/` directory
//! for this test target.

use std::str::FromStr;
use std::sync::{Arc, Barrier};
use std::thread;

use nexusq_core::identity::IdentityId;
use nexusq_core::policy::{
    Policy, PolicyCondition, PolicyContext, PolicyDecision, PolicyEffect, PolicyOperation,
    PolicySet, PolicyTarget,
};
use nexusq_core::vault::{KeyId, KeyStatus, Timestamp};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// An empty attached policy set never authorizes any operation.
    #[test]
    fn empty_policy_set_is_deny_by_default(operation in operation_strategy()) {
        let set = PolicySet::new();
        let context = PolicyContext::new(operation, Timestamp::from_secs(1_700_000_000));

        prop_assert_eq!(set.evaluate(&context).unwrap(), PolicyDecision::NoDecision);
        prop_assert!(!set.evaluate(&context).unwrap().permits());
    }

    /// No matching allow can override an applicable deny, regardless of
    /// how many matching allows occur before or after it.
    #[test]
    fn any_applicable_deny_overrides_allows(
        preceding_allows in 0usize..24,
        following_allows in 0usize..24,
        operation in operation_strategy(),
    ) {
        let mut set = PolicySet::new();
        for index in 0..preceding_allows {
            set.add(allow_policy(&format!("allow-before-{index}"), operation));
        }
        set.add(deny_policy("deny", operation));
        for index in 0..following_allows {
            set.add(allow_policy(&format!("allow-after-{index}"), operation));
        }

        let context = PolicyContext::new(operation, Timestamp::from_secs(1_700_000_000));
        let decision = set.evaluate(&context).unwrap();
        prop_assert_eq!(
            &decision,
            &PolicyDecision::Deny {
                policy_index: preceding_allows,
                reason: "property-test deny".to_owned(),
            }
        );
        prop_assert!(!decision.permits());
    }

    /// Adding a rule for a different operation cannot change the decision.
    #[test]
    fn unrelated_operation_rules_do_not_change_decision(
        operation in operation_strategy(),
        other in operation_strategy(),
        deny in any::<bool>(),
    ) {
        prop_assume!(operation != other);
        let context = PolicyContext::new(operation, Timestamp::from_secs(1_700_000_000));
        let mut set = PolicySet::new();
        set.add(allow_policy("matching-allow", operation));
        let before = set.evaluate(&context).unwrap();
        let unrelated = if deny {
            deny_policy("unrelated-deny", other)
        } else {
            allow_policy("unrelated-allow", other)
        };
        set.add(unrelated);

        prop_assert_eq!(&set.evaluate(&context).unwrap(), &before);
        prop_assert!(before.permits());
    }

    /// A rule with no covered operations never matches any context.
    #[test]
    fn empty_operation_list_never_authorizes(operation in operation_strategy()) {
        let mut set = PolicySet::new();
        set.add(Policy::new("empty-operations", PolicyEffect::Allow)
            .for_operations(Vec::new())
            .on(PolicyTarget::All));
        let context = PolicyContext::new(operation, Timestamp::from_secs(1_700_000_000));

        prop_assert_eq!(set.evaluate(&context).unwrap(), PolicyDecision::NoDecision);
    }

    /// Evaluation is deterministic and has no hidden mutable state.
    #[test]
    fn repeated_evaluation_is_idempotent(
        operation in operation_strategy(),
        allow_count in 0usize..12,
        add_deny in any::<bool>(),
    ) {
        let mut set = PolicySet::new();
        for index in 0..allow_count {
            set.add(allow_policy(&format!("allow-{index}"), operation));
        }
        if add_deny {
            set.add(deny_policy("deny", operation));
        }
        let context = PolicyContext::new(operation, Timestamp::from_secs(1_700_000_000));

        let first = set.evaluate(&context).unwrap();
        for _ in 0..8 {
            prop_assert_eq!(&set.evaluate(&context).unwrap(), &first);
        }
    }

    /// An allow rule with a key-specific target only matches that key.
    #[test]
    fn key_target_never_bypasses_resource_boundary(
        target_raw in any::<u128>(),
        context_raw in any::<u128>(),
    ) {
        let target_id = key_id(target_raw);
        let context_id = key_id(context_raw);
        let mut set = PolicySet::new();
        set.add(
            Policy::new("specific-key", PolicyEffect::Allow)
                .for_operations(vec![PolicyOperation::Sign])
                .on(PolicyTarget::Key(target_id.clone()))
        );
        let context = PolicyContext::new(PolicyOperation::Sign, Timestamp::from_secs(1_700_000_000))
            .with_key(context_id, KeyStatus::Active);

        let decision = set.evaluate(&context).unwrap();
        if target_raw == context_raw {
            prop_assert!(decision.is_allow());
        } else {
            prop_assert_eq!(decision, PolicyDecision::NoDecision);
        }
    }

    /// Identity-specific rules cannot authorize a different identity.
    #[test]
    fn identity_target_never_bypasses_identity_boundary(
        target_raw in any::<u128>(),
        context_raw in any::<u128>(),
    ) {
        let target_id = identity_id(target_raw);
        let context_id = identity_id(context_raw);
        let mut set = PolicySet::new();
        set.add(
            Policy::new("specific-identity", PolicyEffect::Allow)
                .for_operations(vec![PolicyOperation::IdentitySign])
                .on(PolicyTarget::Identity(target_id))
        );
        let context = PolicyContext::new(
            PolicyOperation::IdentitySign,
            Timestamp::from_secs(1_700_000_000),
        ).with_identity(context_id);

        let decision = set.evaluate(&context).unwrap();
        if target_raw == context_raw {
            prop_assert!(decision.is_allow());
        } else {
            prop_assert_eq!(decision, PolicyDecision::NoDecision);
        }
    }

    /// Time-window conditions preserve their inclusive/exclusive boundaries.
    #[test]
    fn time_conditions_respect_exact_boundaries(now in 0u64..u64::MAX) {
        let context = PolicyContext::new(
            PolicyOperation::Sign,
            Timestamp::from_secs(now),
        );
        prop_assert!(PolicyCondition::NotBefore(Timestamp::from_secs(now)).holds(&context));
        prop_assert!(!PolicyCondition::NotBefore(Timestamp::from_secs(now + 1)).holds(&context));
        prop_assert!(PolicyCondition::NotAfter(Timestamp::from_secs(now + 1)).holds(&context));
        prop_assert!(!PolicyCondition::NotAfter(Timestamp::from_secs(now)).holds(&context));
    }

    /// A key/identity-specific target cannot match when the context omits
    /// the corresponding resource entirely.
    #[test]
    fn resource_targets_fail_closed_when_resource_is_missing(
        raw in any::<u128>(),
        identity_operation in any::<bool>(),
    ) {
        let target = if identity_operation {
            PolicyTarget::Identity(identity_id(raw))
        } else {
            PolicyTarget::Key(key_id(raw))
        };
        let operation = if identity_operation {
            PolicyOperation::IdentitySign
        } else {
            PolicyOperation::Sign
        };
        let mut set = PolicySet::new();
        set.add(Policy::new("resource-bound", PolicyEffect::Allow)
            .for_operations(vec![operation])
            .on(target));
        let context = PolicyContext::new(operation, Timestamp::from_secs(1_700_000_000));

        prop_assert_eq!(set.evaluate(&context).unwrap(), PolicyDecision::NoDecision);
    }

    /// Missing caller/attestation context must not satisfy guarded rules.
    #[test]
    fn missing_security_context_does_not_satisfy_conditions(
        require_caller in any::<bool>(),
        require_attestation in any::<bool>(),
    ) {
        prop_assume!(require_caller || require_attestation);
        let mut policy = allow_policy("guarded", PolicyOperation::Sign);
        if require_caller {
            policy = policy.and_condition(PolicyCondition::RequiresCaller);
        }
        if require_attestation {
            policy = policy.and_condition(PolicyCondition::RequiresAttestation);
        }
        let mut set = PolicySet::new();
        set.add(policy);
        let context = PolicyContext::new(PolicyOperation::Sign, Timestamp::from_secs(1_700_000_000));

        prop_assert_eq!(set.evaluate(&context).unwrap(), PolicyDecision::NoDecision);
    }
}

/// A shared immutable policy snapshot can be evaluated concurrently without
/// changing the result. Mutations require `&mut self`, so Rust's borrowing
/// rules prevent mutation while shared evaluation references are alive.
#[test]
fn concurrent_evaluation_of_shared_policy_snapshot_is_stable() {
    const THREADS: usize = 8;
    const ITERATIONS: usize = 256;

    let mut policies = PolicySet::new();
    policies.add(allow_policy("allow-sign", PolicyOperation::Sign));
    policies.add(deny_policy("deny-sign", PolicyOperation::Sign));
    policies.add(allow_policy("allow-verify", PolicyOperation::Verify));
    let policies = Arc::new(policies);

    let sign = Arc::new(PolicyContext::new(
        PolicyOperation::Sign,
        Timestamp::from_secs(1_700_000_000),
    ));
    let verify = Arc::new(PolicyContext::new(
        PolicyOperation::Verify,
        Timestamp::from_secs(1_700_000_000),
    ));
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut workers = Vec::with_capacity(THREADS);

    for _ in 0..THREADS {
        let policies = Arc::clone(&policies);
        let sign = Arc::clone(&sign);
        let verify = Arc::clone(&verify);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..ITERATIONS {
                assert!(policies.evaluate(&sign).unwrap().is_deny());
                assert!(policies.evaluate(&verify).unwrap().is_allow());
            }
        }));
    }

    for worker in workers {
        worker.join().expect("policy evaluation worker panicked");
    }
}

fn allow_policy(label: &str, operation: PolicyOperation) -> Policy {
    Policy::new(label, PolicyEffect::Allow)
        .for_operations(vec![operation])
        .on(PolicyTarget::All)
}

fn deny_policy(label: &str, operation: PolicyOperation) -> Policy {
    Policy::new(
        label,
        PolicyEffect::Deny {
            reason: "property-test deny".to_owned(),
        },
    )
    .for_operations(vec![operation])
    .on(PolicyTarget::All)
}

fn key_id(value: u128) -> KeyId {
    KeyId::from_str(&format!("nqk_ed25519_{value:032x}"))
        .expect("formatted property key id is valid")
}

fn identity_id(value: u128) -> IdentityId {
    IdentityId::from_str(&format!("nqi_{value:032x}"))
        .expect("formatted property identity id is valid")
}

fn operation_strategy() -> impl Strategy<Value = PolicyOperation> {
    prop_oneof![
        Just(PolicyOperation::KeyCreate),
        Just(PolicyOperation::KeyActivate),
        Just(PolicyOperation::KeyRotate),
        Just(PolicyOperation::KeyRevoke),
        Just(PolicyOperation::KeyDestroy),
        Just(PolicyOperation::Sign),
        Just(PolicyOperation::Verify),
        Just(PolicyOperation::Encrypt),
        Just(PolicyOperation::Decrypt),
        Just(PolicyOperation::KeyAgreement),
        Just(PolicyOperation::Wrap),
        Just(PolicyOperation::IdentityCreate),
        Just(PolicyOperation::IdentitySign),
        Just(PolicyOperation::IdentityRotateKey),
        Just(PolicyOperation::IdentityRevoke),
        Just(PolicyOperation::CredentialIssue),
        Just(PolicyOperation::CredentialVerify),
        Just(PolicyOperation::CredentialRevoke),
        Just(PolicyOperation::EnvelopeSeal),
        Just(PolicyOperation::EnvelopeOpen),
    ]
}

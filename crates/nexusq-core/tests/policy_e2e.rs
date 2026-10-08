//! End-to-end tests for the policy engine.
//!
//! These tests exercise the interaction between the vault, its
//! policies, and the audit log through the public API. They live
//! outside the crate so they see the same surface a downstream caller
//! would.

use std::fs;

use nexusq_core::policy::{Policy, PolicyEffect, PolicyOperation, PolicySet, PolicyTarget};
use nexusq_core::storage::EventOutcome;
use nexusq_core::vault::{Algorithm, Purpose, Vault};
use tempfile::TempDir;

/// Creates a vault with auditing enabled, returns (vault_path,
/// audit_dir, session) so the test can drive it.
fn setup(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf, Vault) {
    let vault_path = dir.path().join("vault.nqv");
    let audit_dir = dir.path().join("audit");
    fs::create_dir(&audit_dir).unwrap();

    Vault::create(&vault_path, b"vault-pass", None).unwrap();
    let vault = Vault::open(&vault_path).unwrap();

    (vault_path, audit_dir, vault)
}

/// A policy that allows key creation.
fn allow_create() -> Policy {
    Policy::new("allow-create", PolicyEffect::Allow)
        .for_operations(vec![PolicyOperation::KeyCreate])
        .on(PolicyTarget::All)
}

/// A policy that denies key rotation.
fn deny_rotate() -> Policy {
    Policy::new(
        "deny-rotate",
        PolicyEffect::Deny {
            reason: "rotation not allowed".into(),
        },
    )
    .for_operations(vec![PolicyOperation::KeyRotate])
    .on(PolicyTarget::All)
}

#[test]
fn no_policy_engine_allows_everything() {
    let dir = TempDir::new().unwrap();
    let (_vault_path, _audit_dir, vault) = setup(&dir);
    let mut session = vault.unlock(b"vault-pass").unwrap();

    // No policies attached: every operation should work.
    let key_id = session
        .generate_key(Algorithm::Ed25519, Purpose::Sign)
        .unwrap();
    session.activate_key(&key_id).unwrap();
    let _ = session.rotate_key(&key_id).unwrap();
}

#[test]
fn empty_policy_set_denies_everything() {
    let dir = TempDir::new().unwrap();
    let (_vault_path, _audit_dir, vault) = setup(&dir);
    let mut session = vault.unlock(b"vault-pass").unwrap();

    // Attach an empty set: default-deny kicks in.
    session.set_policies(PolicySet::new()).unwrap();

    let err = session
        .generate_key(Algorithm::Ed25519, Purpose::Sign)
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("denied by policy"), "got: {msg}");
}

#[test]
fn explicit_allow_permits_only_the_named_operation() {
    let dir = TempDir::new().unwrap();
    let (_vault_path, _audit_dir, vault) = setup(&dir);
    let mut session = vault.unlock(b"vault-pass").unwrap();

    let mut set = PolicySet::new();
    set.add(allow_create());
    session.set_policies(set).unwrap();

    // KeyCreate is allowed.
    let key_id = session
        .generate_key(Algorithm::Ed25519, Purpose::Sign)
        .unwrap();

    // KeyActivate is not covered: default-deny refuses it.
    let err = session.activate_key(&key_id).unwrap_err();
    assert!(err.to_string().contains("denied by policy"));
}

#[test]
fn explicit_deny_overrides_an_allow() {
    let dir = TempDir::new().unwrap();
    let (_vault_path, _audit_dir, vault) = setup(&dir);
    let mut session = vault.unlock(b"vault-pass").unwrap();

    // Allow KeyCreate and KeyActivate, but deny KeyActivate.
    let mut set = PolicySet::new();
    set.add(allow_create());
    set.add(
        Policy::new("allow-activate", PolicyEffect::Allow)
            .for_operations(vec![PolicyOperation::KeyActivate])
            .on(PolicyTarget::All),
    );
    set.add(
        Policy::new(
            "deny-activate",
            PolicyEffect::Deny {
                reason: "activation frozen".into(),
            },
        )
        .for_operations(vec![PolicyOperation::KeyActivate])
        .on(PolicyTarget::All),
    );
    session.set_policies(set).unwrap();

    // Create works.
    let key_id = session
        .generate_key(Algorithm::Ed25519, Purpose::Sign)
        .unwrap();

    // Activate is denied despite the explicit allow earlier.
    let err = session.activate_key(&key_id).unwrap_err();
    assert!(err.to_string().contains("denied by policy"));
}

#[test]
fn clear_policies_restores_permissive_behavior() {
    let dir = TempDir::new().unwrap();
    let (_vault_path, _audit_dir, vault) = setup(&dir);
    let mut session = vault.unlock(b"vault-pass").unwrap();

    // First deny everything.
    session.set_policies(PolicySet::new()).unwrap();
    assert!(
        session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .is_err()
    );

    // Then clear and verify operations work again.
    session.clear_policies().unwrap();
    session
        .generate_key(Algorithm::Ed25519, Purpose::Sign)
        .unwrap();
}

#[test]
fn denied_operations_are_recorded_in_the_audit_log() {
    let dir = TempDir::new().unwrap();
    let (_vault_path, audit_dir, vault) = setup(&dir);
    let mut session = vault.unlock(b"vault-pass").unwrap();
    session.enable_audit(&audit_dir).unwrap();

    // Policies that allow create but not activate.
    let mut set = PolicySet::new();
    set.add(allow_create());
    session.set_policies(set).unwrap();

    // Create a key (allowed).
    let key_id = session
        .generate_key(Algorithm::Ed25519, Purpose::Sign)
        .unwrap();

    // Try to activate it (denied). The audit log should record the
    // denial before the operation returns.
    let _ = session.activate_key(&key_id);

    // Verify through the authenticated session key and inspect the current segment.
    session.verify_audit().unwrap();
    let events = session.audit_events().unwrap();

    let denied = events
        .iter()
        .find(|e| e.outcome == EventOutcome::Denied)
        .expect("a denied event should be recorded");
    assert_eq!(denied.event_type.as_str(), "key_access_denied");
}

#[test]
fn audit_records_policy_changed_events() {
    let dir = TempDir::new().unwrap();
    let (_vault_path, audit_dir, vault) = setup(&dir);
    let mut session = vault.unlock(b"vault-pass").unwrap();
    session.enable_audit(&audit_dir).unwrap();

    session.set_policies(PolicySet::new()).unwrap();
    session.clear_policies().unwrap();

    session.verify_audit().unwrap();
    let events = session.audit_events().unwrap();

    // Two PolicyChanged events.
    let count = events
        .iter()
        .filter(|e| e.event_type.as_str() == "policy_changed")
        .count();
    assert_eq!(count, 2);
}

#[test]
fn policies_persist_across_lock_and_unlock() {
    let dir = TempDir::new().unwrap();
    let (vault_path, _audit_dir, vault) = setup(&dir);
    let mut session = vault.unlock(b"vault-pass").unwrap();

    let mut set = PolicySet::new();
    set.add(allow_create());
    session.set_policies(set).unwrap();
    session.lock().unwrap();

    // Reopen: the policies should still be attached and enforced.
    let vault = Vault::open(&vault_path).unwrap();
    let session = vault.unlock(b"vault-pass").unwrap();
    assert!(session.policies().is_some());

    // Generate is allowed (KeyCreate), but activation is not.
    let mut session = session;
    let key_id = session
        .generate_key(Algorithm::Ed25519, Purpose::Sign)
        .unwrap();
    assert!(session.activate_key(&key_id).is_err());

    // Silence unused warn.
    let _ = deny_rotate();
}

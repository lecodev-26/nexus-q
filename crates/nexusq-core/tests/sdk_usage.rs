//! Usage test for the public SDK surface.
//!
//! Exercises the crate as an external caller would: import the
//! prelude, create a vault, work with keys, identities, policies and
//! the audit log, and check that everything behaves. This test lives
//! outside the crate so it only sees the public API.

use nexusq_core::prelude::*;
use tempfile::TempDir;

#[test]
fn prelude_imports_the_expected_types() {
    // Compile-time checks: the types are named and usable.
    let _: Option<KeyId> = None;
    let _: Option<IdentityId> = None;
    let _: Option<Algorithm> = None;
    let _: Option<Purpose> = None;
    let _: Option<KeyStatus> = None;
    let _: Option<PolicySet> = None;
    let _: Option<EventType> = None;
    let _: Option<VaultError> = None;
    let _: Option<Error> = None;
    let _: Option<Result<()>> = None;
}

#[test]
fn full_workflow_through_the_public_api() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("vault.nqv");
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir(&audit_dir).unwrap();

    // Create a vault.
    let vault = Vault::create(&vault_path, b"password", Some("sdk-test".into())).unwrap();
    let mut session = vault.unlock(b"password").unwrap();

    // Attach an audit log.
    session.set_audit_dir(&audit_dir).unwrap();

    // Generate and activate a signing key.
    let key_id = session
        .generate_key(Algorithm::Ed25519, Purpose::Sign)
        .unwrap();
    session.activate_key(&key_id).unwrap();

    // Create an identity.
    let identity_id = session.create_identity(Some("alice".into())).unwrap();

    // Sign a message with the identity.
    let message = b"hello, sdk";
    let signature = session.identity_sign(&identity_id, message).unwrap();
    session
        .identity_verify(&identity_id, message, &signature)
        .unwrap();

    // Attach a policy that allows signing only.
    let mut policies = PolicySet::new();
    policies.add(
        Policy::new("allow-sign", PolicyEffect::Allow)
            .for_operations(vec![PolicyOperation::Sign])
            .on(PolicyTarget::All),
    );
    session.set_policies(policies).unwrap();

    // Lock, reopen and confirm the state survived.
    session.lock().unwrap();

    let vault = Vault::open(&vault_path).unwrap();
    let session = vault.unlock(b"password").unwrap();
    assert_eq!(session.key_count(), 3); // identity key + PQ credential key + test signing key
    assert_eq!(session.identity_count(), 1);
    assert!(session.policies().is_some());
    assert!(session.audit_dir().is_some());

    // Verify the authenticated audit chain.
    session.verify_audit().unwrap();
}

#[test]
fn error_type_unifies_subsystems() {
    // A vault error can be turned into the crate-wide error.
    let vault_err = VaultError::WrongPassword;
    let err: Error = vault_err.into();
    assert!(matches!(err, Error::Vault(_)));

    // Same for a crypto error.
    let crypto_err: CryptoError = crypto_error_aead_invalid_key();
    let err: Error = crypto_err.into();
    assert!(matches!(err, Error::Crypto(_)));
}

fn crypto_error_aead_invalid_key() -> CryptoError {
    use nexusq_core::crypto::AeadError;
    CryptoError::Aead(AeadError::InvalidKey)
}

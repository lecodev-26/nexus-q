//! End-to-end integration tests for the storage layer.
//!
//! These tests exercise the vault, the audit log and the backup
//! bundle together, through the public API. They live outside the
//! crate so they see the same surface a downstream caller would.
//!
//! The scenarios here mirror the way NEXUS-Q is meant to be used:
//! open a vault, enable auditing, run a sequence of operations,
//! verify that the audit chain reflects exactly what happened, and
//! restore the vault from a backup.

use std::fs;

use nexusq_core::crypto::sign::Signature;
use nexusq_core::storage::EventType;
use nexusq_core::vault::lifecycle::RevokeReason;
use nexusq_core::vault::{Algorithm, Purpose, Vault};
use tempfile::TempDir;

/// Runs a series of vault operations with auditing enabled and
/// returns the audit log so the caller can inspect it.
fn run_audited_session(
    dir: &TempDir,
) -> (std::path::PathBuf, Vec<nexusq_core::storage::AuditEvent>) {
    let vault_path = dir.path().join("vault.nqv");
    let audit_dir = dir.path().join("audit");
    fs::create_dir(&audit_dir).unwrap();

    Vault::create(&vault_path, b"vault-pass", Some("e2e".to_string())).unwrap();
    let vault = Vault::open(&vault_path).unwrap();
    let mut session = vault.unlock(b"vault-pass").unwrap();
    session.enable_audit(&audit_dir).unwrap();

    // Key lifecycle: create, activate, rotate, revoke.
    let key_a = session
        .generate_key(Algorithm::Ed25519, Purpose::Sign)
        .unwrap();
    session.activate_key(&key_a).unwrap();
    let key_b = session.rotate_key(&key_a).unwrap();
    session.activate_key(&key_b).unwrap();

    let key_c = session
        .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
        .unwrap();
    session.activate_key(&key_c).unwrap();

    // Identity: create and sign.
    let identity_id = session.create_identity(Some("alice".to_string())).unwrap();
    let _sig: Signature = session.identity_sign(&identity_id, b"hello").unwrap();

    // Envelope: seal and open.
    let envelope = session
        .encrypt(&key_c, b"secret payload", b"note".to_vec())
        .unwrap();
    let recovered = session.decrypt(&envelope).unwrap();
    assert_eq!(recovered.as_slice(), b"secret payload");

    // Revoke the first signing key for good measure.
    session
        .revoke_key(&key_b, RevokeReason::Superseded)
        .unwrap();

    session.verify_audit().unwrap();
    let events = session.audit_events().unwrap();
    session.lock().unwrap();
    (vault_path, events)
}

#[test]
fn full_lifecycle_produces_the_expected_audit_chain() {
    let dir = TempDir::new().unwrap();
    let (_vault_path, events) = run_audited_session(&dir);

    // Count events by type.
    let mut counts: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    for event in &events {
        let key = match event.event_type {
            EventType::KeyCreated => "key_created",
            EventType::KeyActivated => "key_activated",
            EventType::KeyRotated => "key_rotated",
            EventType::KeyRevoked => "key_revoked",
            EventType::IdentityCreated => "identity_created",
            EventType::IdentitySigned => "identity_signed",
            EventType::EnvelopeSealed => "envelope_sealed",
            EventType::EnvelopeOpened => "envelope_opened",
            _ => "other",
        };
        *counts.entry(key).or_insert(0) += 1;
    }

    // Two keys created directly (key_a, key_c), one by rotation (key_b),
    // plus one inside create_identity.
    assert_eq!(counts.get("key_created"), Some(&4));
    // Activated: key_a, key_b, key_c and the identity signing key.
    assert_eq!(counts.get("key_activated"), Some(&4));
    assert_eq!(counts.get("key_rotated"), Some(&1));
    assert_eq!(counts.get("key_revoked"), Some(&1));
    assert_eq!(counts.get("identity_created"), Some(&1));
    assert_eq!(counts.get("identity_signed"), Some(&1));
    assert_eq!(counts.get("envelope_sealed"), Some(&1));
    assert_eq!(counts.get("envelope_opened"), Some(&1));

    // No 'other' events in this scenario.
    assert!(!counts.contains_key("other"));
}

#[test]
fn tampering_with_the_audit_chain_is_detected() {
    let dir = TempDir::new().unwrap();
    let (_vault_path, _log) = run_audited_session(&dir);

    // Corrupt a byte inside the segment file.
    let audit_dir = dir.path().join("audit");
    let segment_path = audit_dir.join("audit-00001.nqa");
    let mut bytes = fs::read(&segment_path).unwrap();
    // Flip a byte near the middle of the file.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    fs::write(&segment_path, &bytes).unwrap();

    // Unlocking must fail closed because the audit log is authenticated.
    let vault_path = dir.path().join("vault.nqv");
    let result = nexusq_core::vault::Vault::open(&vault_path)
        .unwrap()
        .unlock(b"vault-pass");
    assert!(result.is_err(), "corrupted segment should be rejected");
}

#[test]
fn backup_and_restore_preserves_the_vault_content() {
    let dir = TempDir::new().unwrap();
    let (vault_path, _events) = run_audited_session(&dir);
    let backup_path = dir.path().join("backup.nqb");
    let restored_path = dir.path().join("restored.nqv");

    // Export using a backup passphrase distinct from the vault password.
    {
        let vault = Vault::open(&vault_path).unwrap();
        let session = vault.unlock(b"vault-pass").unwrap();
        nexusq_core::storage::backup::export(&session, &backup_path, b"backup-pass").unwrap();
        assert!(backup_path.exists());
    }

    // Import into a new vault with a new password.
    nexusq_core::storage::backup::import(
        &backup_path,
        b"backup-pass",
        &restored_path,
        b"new-vault-pass",
    )
    .unwrap();

    // The restored vault opens with the NEW password.
    let restored = Vault::open(&restored_path).unwrap();
    let session = restored.unlock(b"new-vault-pass").unwrap();

    // Same number of keys and identities as the original.
    let original = Vault::open(&vault_path).unwrap();
    let original_session = original.unlock(b"vault-pass").unwrap();
    assert_eq!(session.key_count(), original_session.key_count());
    assert_eq!(session.identity_count(), original_session.identity_count());
    assert_eq!(
        session.body().metadata.vault_id,
        original_session.body().metadata.vault_id
    );
}

#[test]
fn backup_uses_a_separate_passphrase() {
    let dir = TempDir::new().unwrap();
    let (vault_path, _events) = run_audited_session(&dir);
    let backup_path = dir.path().join("backup.nqb");
    let restored_path = dir.path().join("restored.nqv");

    {
        let vault = Vault::open(&vault_path).unwrap();
        let session = vault.unlock(b"vault-pass").unwrap();
        nexusq_core::storage::backup::export(&session, &backup_path, b"backup-pass").unwrap();
    }

    // Trying to import with the vault password (not the backup
    // passphrase) must fail.
    let err =
        nexusq_core::storage::backup::import(&backup_path, b"vault-pass", &restored_path, b"new")
            .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("wrong backup passphrase"), "got: {msg}");
}

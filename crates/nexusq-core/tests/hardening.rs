//! Security hardening: compatibility, corruption, invariants and properties.
use nexusq_core::crypto::{aead, pq_sign};
use nexusq_core::vault::{Algorithm, Purpose, Vault};
use proptest::prelude::*;
use tempfile::TempDir;

#[test]
fn vault_create_open_unlock_lock_reopen_compatibility() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("compat.nqv");
    let vault = Vault::create(&path, b"pw", Some("compat".into())).unwrap();
    let mut session = vault.unlock(b"pw").unwrap();
    let key = session
        .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
        .unwrap();
    session.activate_key(&key).unwrap();
    let envelope = session
        .encrypt(&key, b"compatibility payload", b"metadata".to_vec())
        .unwrap();
    assert_eq!(
        session.decrypt(&envelope).unwrap().as_slice(),
        b"compatibility payload"
    );
    session.lock().unwrap();
    let reopened = Vault::open(&path).unwrap();
    let session = reopened.unlock(b"pw").unwrap();
    assert_eq!(session.key_count(), 1);
    assert_eq!(
        session.decrypt(&envelope).unwrap().as_slice(),
        b"compatibility payload"
    );
}

#[test]
fn vault_wrong_password_never_unlocks() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("wrong-password.nqv");
    Vault::create(&path, b"correct", None).unwrap();
    let vault = Vault::open(&path).unwrap();
    assert!(matches!(
        vault.unlock(b"wrong"),
        Err(nexusq_core::vault::VaultError::WrongPassword)
    ));
}

#[test]
fn vault_truncation_is_rejected_without_panic() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("truncated.nqv");
    Vault::create(&path, b"pw", None).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len().saturating_sub(8));
    std::fs::write(&path, bytes).unwrap();
    let opened = Vault::open(&path).unwrap();
    assert!(opened.unlock(b"pw").is_err());
}

#[test]
fn vault_unknown_version_is_rejected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("version.nqv");
    Vault::create(&path, b"pw", None).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    // Header CBOR is after magic + 4-byte length. The version field is inside
    // CBOR, so mutate bytes and require parse/decrypt rejection rather than
    // trusting a hand-coded offset.
    let original = bytes.clone();
    for i in 8..bytes.len().min(64) {
        bytes[i] ^= 0x01;
    }
    std::fs::write(&path, bytes).unwrap();
    assert!(Vault::open(&path).is_err());
    std::fs::write(&path, original).unwrap();
    assert!(Vault::open(&path).is_ok());
}

#[test]
fn envelope_ciphertext_corruption_is_rejected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("envelope.nqv");
    let vault = Vault::create(&path, b"pw", None).unwrap();
    let mut session = vault.unlock(b"pw").unwrap();
    let key = session
        .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
        .unwrap();
    session.activate_key(&key).unwrap();
    let mut envelope = session.encrypt(&key, b"secret", Vec::new()).unwrap();
    let last = envelope.len() - 1;
    envelope[last] ^= 0x80;
    assert!(session.decrypt(&envelope).is_err());
}

#[test]
fn security_invariants_lock_and_key_lifecycle() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("invariants.nqv");
    let vault = Vault::create(&path, b"pw", None).unwrap();
    let mut session = vault.unlock(b"pw").unwrap();
    let key = session
        .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
        .unwrap();
    assert!(session.encrypt(&key, b"blocked", Vec::new()).is_err());
    session.activate_key(&key).unwrap();
    let envelope = session.encrypt(&key, b"allowed", Vec::new()).unwrap();
    session
        .revoke_key(&key, nexusq_core::vault::RevokeReason::Compromised)
        .unwrap();
    assert!(session.decrypt(&envelope).is_err());
    assert!(
        session
            .encrypt(&key, b"blocked after revoke", Vec::new())
            .is_err()
    );
    session.seal().unwrap();
    assert!(
        session
            .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
            .is_err()
    );
}

proptest! {
    #[test]
    fn aead_roundtrip_property(input in prop::collection::vec(any::<u8>(), 0..4096)) {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let ct = aead::encrypt(aead::Algorithm::Aes256Gcm, &key, &nonce, b"nexusq", &input).unwrap();
        let pt = aead::decrypt(aead::Algorithm::Aes256Gcm, &key, &nonce, b"nexusq", &ct).unwrap();
        prop_assert_eq!(pt, input);
    }

    #[test]
    fn algorithm_identifier_roundtrip(alg in prop::sample::select(Algorithm::all().to_vec())) {
        prop_assert_eq!(alg, alg.as_str().parse().unwrap());
    }
}

#[test]
fn pq_signature_smoke_vectors_are_stable_in_shape() {
    let m = b"nexusq-pq-smoke";
    let ml = pq_sign::MlDsa65KeyPair::generate();
    assert_eq!(ml.public_key().len(), pq_sign::ML_DSA_65_PUBLIC_KEY_LEN);
    assert_eq!(ml.sign(m).len(), pq_sign::ML_DSA_65_SIGNATURE_LEN);
    let slh = pq_sign::SlhDsaShake128fKeyPair::generate();
    assert_eq!(
        slh.public_key().len(),
        pq_sign::SLH_DSA_SHAKE_128F_PUBLIC_KEY_LEN
    );
    assert_eq!(slh.sign(m).len(), pq_sign::SLH_DSA_SHAKE_128F_SIGNATURE_LEN);
}

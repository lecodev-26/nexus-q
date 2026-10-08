//! V2-08 correctness and interoperability regression coverage.
//!
//! These tests exercise the NEXUS-Q serialization boundary against the
//! underlying RustCrypto primitives and cover malformed-input behavior.

use ml_dsa::{KeyInit as _, MlDsa65, SignatureEncoding as _, Signer as _, Verifier as _};
use ml_kem::kem::{Decapsulate as _, Encapsulate as _};
use nexusq_core::crypto::kem::{KemError, hybrid, ml_kem_768};
use nexusq_core::crypto::kem_1024;
use nexusq_core::crypto::pq_sign::{
    ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN, MlDsa65KeyPair, PqSignError,
    ml_dsa_65_verify,
};
use nexusq_core::crypto::sign::{SignError, Signature, VerifyingKey, generate};

#[test]
fn ml_kem_768_wrapper_bytes_interoperate_with_backend() {
    let (secret, public) = ml_kem_768::generate();
    let public_bytes = ml_kem_768::public_key_bytes(&public);

    let backend_key = ml_kem_768::public_key_from_bytes(&public_bytes).unwrap();
    let (backend_ct, backend_ss) = backend_key.encapsulate();
    let wrapper_ss = ml_kem_768::decapsulate(&secret, backend_ct.as_slice()).unwrap();
    assert_eq!(backend_ss.as_slice(), wrapper_ss.as_ref());
}

#[test]
fn ml_kem_768_backend_can_decapsulate_wrapper_ciphertext() {
    let (secret, public) = ml_kem_768::generate();
    let (ciphertext, wrapper_ss) = ml_kem_768::encapsulate(&public);

    let ct: ml_kem::ml_kem_768::Ciphertext = ciphertext.as_slice().try_into().unwrap();
    let backend_ss = secret.decapsulate(&ct);
    assert_eq!(backend_ss.as_slice(), wrapper_ss.as_ref());
}

#[test]
fn ml_kem_1024_hybrid_roundtrip_and_invalid_lengths() {
    let pair = kem_1024::generate();
    let public = pair.public_key_bytes();
    let (ciphertext, sender_secret) = kem_1024::encapsulate(&public).unwrap();
    let receiver_secret = kem_1024::decapsulate(&pair, &ciphertext).unwrap();
    assert_eq!(sender_secret.as_ref(), receiver_secret.as_ref());

    assert!(matches!(
        kem_1024::encapsulate(&public[..public.len() - 1]),
        Err(KemError::InvalidPublicKey)
    ));
    assert!(matches!(
        kem_1024::decapsulate(&pair, &ciphertext[..ciphertext.len() - 1]),
        Err(KemError::InvalidCiphertext)
    ));
}

#[test]
fn x_wing_hybrid_roundtrip_and_transcript_binding() {
    let pair = hybrid::generate();
    let public = pair.public_key_bytes();
    let (ciphertext, sender_secret) = hybrid::encapsulate(&public).unwrap();
    let receiver_secret = hybrid::decapsulate(&pair, &ciphertext).unwrap();
    assert_eq!(sender_secret.as_ref(), receiver_secret.as_ref());

    let mut tampered = ciphertext;
    tampered[hybrid::CIPHERTEXT_LEN - 1] ^= 0x80;
    let tampered_secret = hybrid::decapsulate(&pair, &tampered).unwrap();
    assert_ne!(sender_secret.as_ref(), tampered_secret.as_ref());
}

#[test]
fn ml_dsa_wrapper_bytes_interoperate_with_backend() {
    let pair = MlDsa65KeyPair::generate();
    let message = b"nexusq-v2-interop";
    let signature = pair.sign(message);
    let public = pair.public_key();

    assert_eq!(public.len(), ML_DSA_65_PUBLIC_KEY_LEN);
    assert_eq!(signature.len(), ML_DSA_65_SIGNATURE_LEN);

    let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(public.as_slice()).unwrap();
    let backend_vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded);
    let backend_sig = ml_dsa::Signature::<MlDsa65>::try_from(signature.as_slice()).unwrap();
    backend_vk.verify(message, &backend_sig).unwrap();

    ml_dsa_65_verify(&public, message, &signature).unwrap();
    assert!(matches!(
        ml_dsa_65_verify(&public, b"wrong", &signature),
        Err(PqSignError::VerificationFailed)
    ));
}

#[test]
fn ml_dsa_backend_signature_is_accepted_by_wrapper() {
    let pair = MlDsa65KeyPair::generate();
    let seed = pair.secret_key();
    let seed_array: [u8; 32] = seed.as_slice().try_into().unwrap();
    let backend_signing = ml_dsa::SigningKey::<MlDsa65>::new(&seed_array.into());
    let message = b"backend-to-wrapper";
    let backend_signature = backend_signing.try_sign(message).unwrap().to_bytes();

    ml_dsa_65_verify(&pair.public_key(), message, backend_signature.as_slice()).unwrap();
}

#[test]
fn malformed_pqc_inputs_are_rejected_at_public_boundary() {
    let pair = MlDsa65KeyPair::generate();
    assert!(matches!(
        MlDsa65KeyPair::from_secret_key(&[0u8; 31]),
        Err(PqSignError::InvalidKey)
    ));
    assert!(matches!(
        nexusq_core::crypto::pq_sign::MlDsa65VerifyingKey::from_public_key(&[0u8; 31]),
        Err(PqSignError::InvalidKey)
    ));
    assert!(matches!(
        ml_dsa_65_verify(&pair.public_key(), b"m", &[0u8; 10]),
        Err(PqSignError::InvalidSignature)
    ));
    assert!(matches!(
        ml_kem_768::public_key_from_bytes(&[0u8; 10]),
        Err(KemError::InvalidPublicKey)
    ));
    assert!(matches!(
        ml_kem_768::decapsulate(&ml_kem_768::generate().0, &[0u8; 10]),
        Err(KemError::InvalidCiphertext)
    ));
}

#[test]
fn ed25519_serialization_and_malformed_signature_regression() {
    let pair = generate();
    let message = b"nexusq-v2-ed25519";
    let signature = pair.signing.sign(message);
    let public = pair.verifying.to_bytes();
    let parsed = VerifyingKey::from_bytes(&public).unwrap();
    parsed.verify(message, &signature).unwrap();

    let raw = signature.to_bytes();
    let mut tampered = raw.to_vec();
    tampered[0] ^= 1;
    let tampered_signature = Signature::from_bytes(&tampered).unwrap();
    assert!(matches!(
        parsed.verify(message, &tampered_signature),
        Err(SignError::VerificationFailed)
    ));
}

#[test]
fn canonical_kem_sizes_remain_stable() {
    assert_eq!(ml_kem_768::PUBLIC_KEY_LEN, 1184);
    assert_eq!(ml_kem_768::CIPHERTEXT_LEN, 1088);
    assert_eq!(hybrid::PUBLIC_KEY_LEN, 1216);
    assert_eq!(hybrid::CIPHERTEXT_LEN, 1120);
}

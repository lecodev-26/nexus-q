//! Digital signatures.
//!
//! Ed25519 (RFC 8032) is the only algorithm exposed here. It is mature,
//! widely deployed and audited. Post-quantum signatures (ML-DSA) are
//! deferred until the RustCrypto crate stabilizes; see ADR 0001.
//!
//! Two types are used:
//!
//! - [`SigningKey`] holds the private half. It is zeroized on drop.
//! - [`VerifyingKey`] holds the public half and can be freely shared.
//!
//! Signatures are detached: they are a separate byte string from the
//! message, and both are required to verify.

use ed25519_dalek::{
    Signature as DalekSignature, Signer as _, SigningKey as DalekSigningKey, Verifier as _,
    VerifyingKey as DalekVerifyingKey,
};
use zeroize::Zeroizing;

/// Length in bytes of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Length in bytes of an Ed25519 verifying (public) key.
pub const VERIFYING_KEY_LEN: usize = 32;

/// Length in bytes of an Ed25519 signing (secret) key.
pub const SIGNING_KEY_LEN: usize = 32;

/// Errors returned by the signature module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The signing key length was wrong.
    #[error("invalid signing key length")]
    InvalidSigningKey,

    /// The verifying key length was wrong.
    #[error("invalid verifying key length")]
    InvalidVerifyingKey,

    /// The signature length was wrong.
    #[error("invalid signature length")]
    InvalidSignature,

    /// Verification failed: wrong key, wrong message, or tampered
    /// signature.
    #[error("signature verification failed")]
    VerificationFailed,
}

/// An Ed25519 signing key (private).
///
/// Zeroized when dropped.
pub struct SigningKey(DalekSigningKey);

/// An Ed25519 verifying key (public).
#[derive(Debug, Clone, Copy)]
pub struct VerifyingKey(DalekVerifyingKey);

/// An Ed25519 detached signature.
#[derive(Debug, Clone, Copy)]
pub struct Signature(DalekSignature);

/// A signing / verifying key pair.
pub struct KeyPair {
    /// The private signing key.
    pub signing: SigningKey,
    /// The public verifying key.
    pub verifying: VerifyingKey,
}

/// Generates a fresh Ed25519 key pair using the OS RNG.
///
/// # Panics
///
/// Panics if the OS RNG fails.
#[must_use]
pub fn generate() -> KeyPair {
    let mut seed = Zeroizing::new([0u8; SIGNING_KEY_LEN]);
    getrandom::fill(seed.as_mut()).expect("OS RNG failed");
    let signing = DalekSigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    KeyPair {
        signing: SigningKey(signing),
        verifying: VerifyingKey(verifying),
    }
}

impl SigningKey {
    /// Parses a signing key from 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSigningKey`] if the length is wrong.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        let arr: [u8; SIGNING_KEY_LEN] =
            bytes.try_into().map_err(|_| SignError::InvalidSigningKey)?;
        Ok(Self(DalekSigningKey::from_bytes(&arr)))
    }

    /// Returns the verifying key corresponding to this signing key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Serializes the signing key to its 32-byte seed.
    ///
    /// The seed is what `from_bytes` accepts, and what the vault stores
    /// wrapped under its KEK. The buffer is wrapped in [`Zeroizing`] so
    /// it is cleared on drop.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; SIGNING_KEY_LEN]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// Signs `message`, producing a detached signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }
}

impl VerifyingKey {
    /// Parses a verifying key from 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidVerifyingKey`] if the length is wrong
    /// or the key is not a valid curve point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        let arr: [u8; VERIFYING_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| SignError::InvalidVerifyingKey)?;
        let vk = DalekVerifyingKey::from_bytes(&arr).map_err(|_| SignError::InvalidVerifyingKey)?;
        Ok(Self(vk))
    }

    /// Serializes the verifying key to 32 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verifies a detached `signature` over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::VerificationFailed`] if the signature does
    /// not match.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignError> {
        self.0
            .verify(message, &signature.0)
            .map_err(|_| SignError::VerificationFailed)
    }
}

impl Signature {
    /// Parses a signature from 64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidSignature`] if the length is wrong.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        let arr: [u8; SIGNATURE_LEN] = bytes.try_into().map_err(|_| SignError::InvalidSignature)?;
        Ok(Self(DalekSignature::from_bytes(&arr)))
    }

    /// Serializes the signature to 64 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; SIGNATURE_LEN]> {
        Zeroizing::new(self.0.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let pair = generate();
        let msg = b"nexusq signature test";
        let sig = pair.signing.sign(msg);
        pair.verifying.verify(msg, &sig).unwrap();
    }

    #[test]
    fn verify_fails_on_different_message() {
        let pair = generate();
        let sig = pair.signing.sign(b"original");
        let err = pair.verifying.verify(b"tampered", &sig);
        assert!(matches!(err, Err(SignError::VerificationFailed)));
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let alice = generate();
        let bob = generate();
        let sig = alice.signing.sign(b"hello");
        let err = bob.verifying.verify(b"hello", &sig);
        assert!(matches!(err, Err(SignError::VerificationFailed)));
    }

    #[test]
    fn verify_fails_on_tampered_signature() {
        let pair = generate();
        let msg = b"message";
        let sig = pair.signing.sign(msg);
        let mut bytes = sig.to_bytes().to_vec();
        bytes[0] ^= 0x01;
        let bad_sig = Signature::from_bytes(&bytes).unwrap();
        let err = pair.verifying.verify(msg, &bad_sig);
        assert!(matches!(err, Err(SignError::VerificationFailed)));
    }

    #[test]
    fn key_serialization_roundtrip() {
        let pair = generate();
        let vk_bytes = pair.verifying.to_bytes();

        let parsed = VerifyingKey::from_bytes(&vk_bytes).unwrap();
        let sig = pair.signing.sign(b"test");
        parsed.verify(b"test", &sig).unwrap();
    }

    #[test]
    fn signing_key_serialization_roundtrip() {
        let pair = generate();
        let sk_bytes = {
            // Extract the raw 32 bytes of the signing key.
            // ed25519-dalek exposes them via `to_bytes`.
            use ed25519_dalek::SigningKey as DalekSigningKey;
            let raw: [u8; SIGNING_KEY_LEN] = {
                // Reconstruct the dalek key from our wrapper.
                let dalek: &DalekSigningKey = &pair.signing.0;
                dalek.to_bytes()
            };
            raw
        };

        let parsed = SigningKey::from_bytes(&sk_bytes).unwrap();
        // Sign with the parsed key, verify with the original verifying key.
        let sig = parsed.sign(b"roundtrip");
        pair.verifying.verify(b"roundtrip", &sig).unwrap();
    }

    #[test]
    fn short_verifying_key_rejected() {
        assert!(matches!(
            VerifyingKey::from_bytes(&[0u8; 10]),
            Err(SignError::InvalidVerifyingKey)
        ));
    }

    #[test]
    fn short_signature_rejected() {
        assert!(matches!(
            Signature::from_bytes(&[0u8; 10]),
            Err(SignError::InvalidSignature)
        ));
    }

    #[test]
    fn signing_key_serialization_is_reversible() {
        let pair = generate();
        let seed = pair.signing.to_bytes();

        let restored = SigningKey::from_bytes(seed.as_ref()).unwrap();
        let sig = restored.sign(b"roundtrip");
        pair.verifying.verify(b"roundtrip", &sig).unwrap();
    }

    #[test]
    fn short_signing_key_rejected() {
        assert!(matches!(
            SigningKey::from_bytes(&[0u8; 10]),
            Err(SignError::InvalidSigningKey)
        ));
    }
}

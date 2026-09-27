//! Authenticated encryption with associated data.
//!
//! Two algorithms are available: AES-256-GCM and ChaCha20-Poly1305.
//! Both take a 32-byte key, a 12-byte nonce and optional associated data
//! (AAD). The AAD is authenticated but not encrypted; callers use it to
//! bind a ciphertext to its context (version byte, key id, metadata).
//!
//! Nonce uniqueness is the caller's responsibility. Reusing a nonce with
//! the same key is a critical failure of both algorithms; the API cannot
//! detect it in general, but [`random_nonce`] is provided as the safe
//! default for typical use.

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};

use super::random::{RandomError, RandomSource};

/// Length in bytes of an AEAD key.
pub const KEY_LEN: usize = 32;

/// Length in bytes of an AEAD nonce.
pub const NONCE_LEN: usize = 12;

/// Length in bytes of an AEAD authentication tag.
pub const TAG_LEN: usize = 16;

/// Algorithms supported by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

/// Errors returned by the AEAD module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AeadError {
    /// The key length did not match [`KEY_LEN`].
    #[error("invalid key length")]
    InvalidKey,

    /// The nonce length did not match [`NONCE_LEN`].
    #[error("invalid nonce length")]
    InvalidNonce,

    /// Decryption failed: wrong key, wrong AAD, or tampered ciphertext.
    ///
    /// The three cases are indistinguishable by design.
    #[error("decryption failed")]
    Decrypt,

    /// Encryption failed (rare; typically only if the underlying
    /// implementation rejects the parameters).
    #[error("encryption failed")]
    Encrypt,
}

impl From<RandomError> for AeadError {
    fn from(_: RandomError) -> Self {
        // Randomness failure is reported as encryption failure at this
        // level; callers that need the distinction should call
        // `random_nonce` explicitly.
        Self::Encrypt
    }
}

/// Generates a random nonce using `source`.
///
/// # Errors
///
/// Propagates the underlying source's failure.
pub fn random_nonce<S: RandomSource>(source: &S) -> Result<[u8; NONCE_LEN], RandomError> {
    let mut nonce = [0u8; NONCE_LEN];
    source.fill_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Encrypts `plaintext` with `key`, `nonce` and `aad` using `algorithm`.
///
/// # Errors
///
/// Returns [`AeadError::InvalidKey`] if `key` is not [`KEY_LEN`] bytes,
/// [`AeadError::InvalidNonce`] if `nonce` is not [`NONCE_LEN`] bytes, or
/// [`AeadError::Encrypt`] if the underlying primitive fails.
pub fn encrypt(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if key.len() != KEY_LEN {
        return Err(AeadError::InvalidKey);
    }
    if nonce.len() != NONCE_LEN {
        return Err(AeadError::InvalidNonce);
    }

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
            let n = AesNonce::try_from(nonce).map_err(|_| AeadError::InvalidNonce)?;
            cipher.encrypt(&n, payload).map_err(|_| AeadError::Encrypt)
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
            let n = ChaChaNonce::try_from(nonce).map_err(|_| AeadError::InvalidNonce)?;
            cipher.encrypt(&n, payload).map_err(|_| AeadError::Encrypt)
        }
    }
}

/// Decrypts `ciphertext` with `key`, `nonce` and `aad` using `algorithm`.
///
/// # Errors
///
/// Returns [`AeadError::InvalidKey`] if `key` is not [`KEY_LEN`] bytes,
/// [`AeadError::InvalidNonce`] if `nonce` is not [`NONCE_LEN`] bytes, or
/// [`AeadError::Decrypt`] if authentication fails (wrong key, wrong AAD,
/// or tampered ciphertext).
pub fn decrypt(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if key.len() != KEY_LEN {
        return Err(AeadError::InvalidKey);
    }
    if nonce.len() != NONCE_LEN {
        return Err(AeadError::InvalidNonce);
    }

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
            let n = AesNonce::try_from(nonce).map_err(|_| AeadError::InvalidNonce)?;
            cipher.decrypt(&n, payload).map_err(|_| AeadError::Decrypt)
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
            let n = ChaChaNonce::try_from(nonce).map_err(|_| AeadError::InvalidNonce)?;
            cipher.decrypt(&n, payload).map_err(|_| AeadError::Decrypt)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x24; NONCE_LEN];
    const AAD: &[u8] = b"nexusq-aead-test";
    const MSG: &[u8] = b"the quick brown fox jumps over the lazy dog";

    fn roundtrip(alg: Algorithm) {
        let ct = encrypt(alg, &KEY, &NONCE, AAD, MSG).unwrap();
        assert_ne!(ct.as_slice(), MSG);
        let pt = decrypt(alg, &KEY, &NONCE, AAD, &ct).unwrap();
        assert_eq!(pt.as_slice(), MSG);
    }

    #[test]
    fn aes_gcm_roundtrip() {
        roundtrip(Algorithm::Aes256Gcm);
    }

    #[test]
    fn chacha20poly1305_roundtrip() {
        roundtrip(Algorithm::ChaCha20Poly1305);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut ct = encrypt(Algorithm::Aes256Gcm, &KEY, &NONCE, AAD, MSG).unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(
            decrypt(Algorithm::Aes256Gcm, &KEY, &NONCE, AAD, &ct),
            Err(AeadError::Decrypt)
        ));
    }

    #[test]
    fn tampered_tag_fails() {
        let mut ct = encrypt(Algorithm::Aes256Gcm, &KEY, &NONCE, AAD, MSG).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(
            decrypt(Algorithm::Aes256Gcm, &KEY, &NONCE, AAD, &ct),
            Err(AeadError::Decrypt)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let ct = encrypt(Algorithm::Aes256Gcm, &KEY, &NONCE, AAD, MSG).unwrap();
        let err = decrypt(Algorithm::Aes256Gcm, &KEY, &NONCE, b"wrong", &ct);
        assert!(matches!(err, Err(AeadError::Decrypt)));
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(Algorithm::Aes256Gcm, &KEY, &NONCE, AAD, MSG).unwrap();
        let other_key = [0x43; KEY_LEN];
        let err = decrypt(Algorithm::Aes256Gcm, &other_key, &NONCE, AAD, &ct);
        assert!(matches!(err, Err(AeadError::Decrypt)));
    }

    #[test]
    fn short_key_rejected() {
        assert!(matches!(
            encrypt(Algorithm::Aes256Gcm, &[0u8; 16], &NONCE, AAD, MSG),
            Err(AeadError::InvalidKey)
        ));
    }

    #[test]
    fn short_nonce_rejected() {
        assert!(matches!(
            encrypt(Algorithm::Aes256Gcm, &KEY, &[0u8; 8], AAD, MSG),
            Err(AeadError::InvalidNonce)
        ));
    }

    #[test]
    fn random_nonce_has_expected_length() {
        let src = crate::crypto::random::OsRandomSource::new();
        let n = random_nonce(&src).unwrap();
        assert_eq!(n.len(), NONCE_LEN);
    }
}

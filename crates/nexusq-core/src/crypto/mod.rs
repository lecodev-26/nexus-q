//! Cryptographic primitives.
//!
//! Every primitive in this module returns a specific error type
//! (`RandomError`, `KdfError`, `AeadError`, `KemError`, `SignError`).
//! [`CryptoError`] unifies them so callers that do not care about the
//! distinction can use a single type.

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod random;
pub mod sign;

pub use aead::{AeadError, Algorithm, decrypt, encrypt, random_nonce};
pub use hash::{sha3_256, sha3_512, sha256, sha512};
pub use kdf::{KdfError, argon2id, hkdf_sha256};
pub use kem::KemError;
pub use random::{OsRandomSource, RandomError, RandomSource};
pub use sign::{KeyPair, SignError, Signature, SigningKey, VerifyingKey};

/// Error type for every cryptographic primitive.
///
/// Each variant wraps the error of a specific primitive. Use this
/// when a function may fail in several ways and the caller only needs
/// to know that something in the crypto layer went wrong.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Randomness source failed.
    #[error("random error: {0}")]
    Random(#[from] RandomError),

    /// Key derivation failed.
    #[error("kdf error: {0}")]
    Kdf(#[from] KdfError),

    /// AEAD encryption or decryption failed.
    #[error("aead error: {0}")]
    Aead(#[from] AeadError),

    /// Key encapsulation or decapsulation failed.
    #[error("kem error: {0}")]
    Kem(#[from] KemError),

    /// Signature creation or verification failed.
    #[error("signature error: {0}")]
    Sign(#[from] SignError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_random_error() {
        let err: CryptoError = RandomError::Unavailable.into();
        assert!(matches!(err, CryptoError::Random(_)));
    }

    #[test]
    fn from_kdf_error() {
        let err: CryptoError = KdfError::ZeroLength.into();
        assert!(matches!(err, CryptoError::Kdf(_)));
    }

    #[test]
    fn from_aead_error() {
        let err: CryptoError = AeadError::InvalidKey.into();
        assert!(matches!(err, CryptoError::Aead(_)));
    }

    #[test]
    fn from_kem_error() {
        let err: CryptoError = KemError::InvalidPublicKey.into();
        assert!(matches!(err, CryptoError::Kem(_)));
    }

    #[test]
    fn from_sign_error() {
        let err: CryptoError = SignError::InvalidSignature.into();
        assert!(matches!(err, CryptoError::Sign(_)));
    }

    #[test]
    fn display_is_prefixed_by_family() {
        let err: CryptoError = AeadError::InvalidKey.into();
        assert!(err.to_string().starts_with("aead error:"));
    }
}

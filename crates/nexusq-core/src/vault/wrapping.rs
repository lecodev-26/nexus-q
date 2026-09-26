//! Wrapping and unwrapping key material.
//!
//! Key material in the vault is never stored in plaintext. Each
//! [`WrappedKeyMaterial`](super::WrappedKeyMaterial) is the result of
//! AEAD-encrypting the raw material under the vault's KEK.
//!
//! ## Wire layout
//!
//! A wrapped blob is:
//!
//! ```text
//! [nonce: 12 bytes][ciphertext || tag: N + 16 bytes]
//! ```
//!
//! The nonce is stored at the front because AEAD does not carry it
//! inside the ciphertext. Every wrap uses a fresh random nonce, so two
//! wraps of the same material under the same KEK produce different
//! blobs (this is normal for AEAD and not a problem).
//!
//! ## Associated data
//!
//! The AAD binds the wrapped material to its owning [`KeyId`]. If an
//! attacker copies a wrapped blob from one key's record to another, the
//! tag fails to verify and the unwrap is refused.
//!
//! See `docs/KEY_MANAGEMENT.md` §4 and `docs/STORAGE.md` §4.

use zeroize::Zeroizing;

use crate::crypto::aead::{self, AeadError, Algorithm as AeadAlgorithm};
use crate::crypto::random::{OsRandomSource, RandomError, RandomSource};

use super::key_id::KeyId;

/// Length of the nonce prefix in a wrapped blob.
pub const NONCE_LEN: usize = aead::NONCE_LEN;

/// Length of the AEAD tag appended to the ciphertext.
pub const TAG_LEN: usize = aead::TAG_LEN;

/// Errors returned by wrapping and unwrapping.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WrappingError {
    /// The wrapped blob was too short to contain a nonce and a tag.
    #[error("wrapped material is truncated")]
    Truncated,

    /// The AEAD operation failed, which almost always means the KEK or
    /// the AAD is wrong.
    #[error("aead operation failed")]
    Aead(#[from] AeadError),

    /// Randomness generation failed while producing a nonce.
    #[error("randomness unavailable")]
    Random(#[from] RandomError),
}

/// Wraps `material` under `kek`, binding it to `key_id`.
///
/// Returns the bytes to store in
/// [`WrappedKeyMaterial`](super::WrappedKeyMaterial).
///
/// # Errors
///
/// Returns [`WrappingError::Random`] if a fresh nonce cannot be drawn,
/// or [`WrappingError::Aead`] if the encryption fails (in practice this
/// only happens for invalid key lengths, which we control).
pub fn wrap(material: &[u8], kek: &[u8], key_id: &KeyId) -> Result<Vec<u8>, WrappingError> {
    let mut rng = OsRandomSource::new();
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce)?;

    let aad = key_id.as_str().as_bytes();
    let ciphertext = aead::encrypt(AeadAlgorithm::Aes256Gcm, kek, &nonce, aad, material)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unwraps a blob produced by [`wrap`].
///
/// Returns the raw key material inside a [`Zeroizing`] buffer, so it is
/// cleared from memory when the caller drops it.
///
/// # Errors
///
/// Returns [`WrappingError::Truncated`] if the blob is too short, or
/// [`WrappingError::Aead`] if authentication fails (wrong KEK, wrong
/// `key_id`, or a tampered blob).
pub fn unwrap(
    wrapped: &[u8],
    kek: &[u8],
    key_id: &KeyId,
) -> Result<Zeroizing<Vec<u8>>, WrappingError> {
    if wrapped.len() < NONCE_LEN + TAG_LEN {
        return Err(WrappingError::Truncated);
    }
    let (nonce, ciphertext) = wrapped.split_at(NONCE_LEN);

    let aad = key_id.as_str().as_bytes();
    let plaintext = aead::decrypt(AeadAlgorithm::Aes256Gcm, kek, nonce, aad, ciphertext)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key_id() -> KeyId {
        let mut rng = OsRandomSource::new();
        KeyId::generate(&mut rng, "ed25519").unwrap()
    }

    const KEK: [u8; 32] = [0x42u8; 32];

    #[test]
    fn wrap_then_unwrap_roundtrip() {
        let id = sample_key_id();
        let material = b"secret key material";
        let wrapped = wrap(material, &KEK, &id).unwrap();
        let unwrapped = unwrap(&wrapped, &KEK, &id).unwrap();
        assert_eq!(unwrapped.as_slice(), material);
    }

    #[test]
    fn wrap_produces_expected_length() {
        let id = sample_key_id();
        let material = b"12345678";
        let wrapped = wrap(material, &KEK, &id).unwrap();
        // nonce + ciphertext (same length as material) + tag
        assert_eq!(wrapped.len(), NONCE_LEN + material.len() + TAG_LEN);
    }

    #[test]
    fn two_wraps_of_same_material_differ() {
        let id = sample_key_id();
        let material = b"12345678";
        let a = wrap(material, &KEK, &id).unwrap();
        let b = wrap(material, &KEK, &id).unwrap();
        assert_ne!(a, b, "each wrap should use a fresh nonce");
    }

    #[test]
    fn unwrap_rejects_wrong_kek() {
        let id = sample_key_id();
        let wrapped = wrap(b"data", &KEK, &id).unwrap();
        let wrong_kek = [0x43u8; 32];
        assert!(unwrap(&wrapped, &wrong_kek, &id).is_err());
    }

    #[test]
    fn unwrap_rejects_wrong_key_id() {
        let id_a = sample_key_id();
        let id_b = sample_key_id();
        let wrapped = wrap(b"data", &KEK, &id_a).unwrap();
        assert!(unwrap(&wrapped, &KEK, &id_b).is_err());
    }

    #[test]
    fn unwrap_rejects_truncated_blob() {
        let id = sample_key_id();
        let truncated = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        assert!(matches!(
            unwrap(&truncated, &KEK, &id),
            Err(WrappingError::Truncated)
        ));
    }

    #[test]
    fn unwrap_rejects_tampered_ciphertext() {
        let id = sample_key_id();
        let mut wrapped = wrap(b"data", &KEK, &id).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        assert!(unwrap(&wrapped, &KEK, &id).is_err());
    }

    #[test]
    fn unwrap_rejects_tampered_nonce() {
        let id = sample_key_id();
        let mut wrapped = wrap(b"data", &KEK, &id).unwrap();
        wrapped[0] ^= 0x01;
        assert!(unwrap(&wrapped, &KEK, &id).is_err());
    }
}

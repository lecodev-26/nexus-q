//! Key derivation functions.
//!
//! Two functions live here:
//!
//! - [`hkdf_sha256`] derives subkeys from high-entropy input (a master
//!   key, a shared secret from a KEM, etc.). Never use it on passwords.
//! - [`argon2id`] derives a key from a user-supplied password. Slow by
//!   design; tuned in `docs/CRYPTOGRAPHY.md` §4.3.
//!
//! Domain separation is mandatory: every call site must pass a distinct
//! `info` (HKDF) or use a distinct salt (Argon2id).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Output length in bytes for derived keys.
pub const DERIVED_KEY_LEN: usize = 32;

/// Salt length in bytes for Argon2id.
pub const ARGON2_SALT_LEN: usize = 16;

/// Memory cost for Argon2id, in kibibytes (64 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;

/// Iteration count for Argon2id.
pub const ARGON2_ITERATIONS: u32 = 3;

/// Parallelism factor for Argon2id.
pub const ARGON2_PARALLELISM: u32 = 1;

/// Errors returned by the KDF module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KdfError {
    /// The output length requested was zero.
    #[error("output length must be greater than zero")]
    ZeroLength,

    /// Argon2 rejected the salt length.
    #[error("invalid salt length")]
    InvalidSalt,

    /// Argon2 failed to derive a key (bad parameters or internal error).
    #[error("argon2 derivation failed")]
    Argon2Failure,

    /// HKDF failed to expand the requested output length.
    #[error("hkdf expansion failed")]
    HkdfExpand,
}

/// Derives a 32-byte key from `ikm` using HKDF-SHA256.
///
/// `info` is a domain-separation string. Two calls with the same `ikm`
/// and different `info` produce unrelated outputs, which is what lets
/// NEXUS-Q use one master key for many purposes.
///
/// `salt` is optional; pass `None` when `ikm` is already uniformly
/// random. Always pass a salt when deriving from a Diffie-Hellman
/// shared secret or similar non-uniform input.
///
/// # Errors
///
/// Returns [`KdfError::HkdfExpand`] if the underlying HKDF rejects the
/// requested output length.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, KdfError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    hk.expand(info, okm.as_mut())
        .map_err(|_| KdfError::HkdfExpand)?;
    Ok(okm)
}

/// Derives a 32-byte key from `password` using Argon2id.
///
/// The parameters are fixed by the module constants and documented in
/// `docs/CRYPTOGRAPHY.md` §4.3. The salt must be unique per password;
/// callers typically generate it with [`crate::crypto::random`] and
/// store it alongside the derived key's verifier.
///
/// # Errors
///
/// Returns [`KdfError::InvalidSalt`] if `salt` is shorter than
/// [`ARGON2_SALT_LEN`], and [`KdfError::Argon2Failure`] if Argon2 rejects
/// the parameters or fails internally.
pub fn argon2id(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, KdfError> {
    if salt.len() < ARGON2_SALT_LEN {
        return Err(KdfError::InvalidSalt);
    }

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|_| KdfError::Argon2Failure)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| KdfError::Argon2Failure)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // HKDF test vectors from RFC 5869, Appendix A.1 (SHA-256).

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected =
            hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
                .unwrap();

        let okm = hkdf_sha256(&ikm, Some(&salt), &info).unwrap();
        assert_eq!(okm.as_slice(), expected.as_slice());
    }

    #[test]
    fn hkdf_rfc5869_test_case_3_no_salt() {
        // RFC 5869 A.3 uses a zero-length salt. The RFC treats this the
        // same as HKDF with salt = HashLen zero bytes. We pass `None`
        // and expect the RFC's expected output.
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info = b"";
        let expected =
            hex::decode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")
                .unwrap();

        let okm = hkdf_sha256(&ikm, None, info).unwrap();
        assert_eq!(okm.as_slice(), expected.as_slice());
    }

    #[test]
    fn hkdf_info_changes_output() {
        let ikm = b"shared secret";
        let a = hkdf_sha256(ikm, None, b"purpose-a").unwrap();
        let b = hkdf_sha256(ikm, None, b"purpose-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn argon2id_rejects_short_salt() {
        let err = argon2id(b"password", b"short").unwrap_err();
        assert!(matches!(err, KdfError::InvalidSalt));
    }

    #[test]
    fn argon2id_is_deterministic_with_same_inputs() {
        let salt = [0u8; ARGON2_SALT_LEN];
        let a = argon2id(b"correct horse battery staple", &salt).unwrap();
        let b = argon2id(b"correct horse battery staple", &salt).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn argon2id_differs_with_different_salt() {
        let salt_a = [0u8; ARGON2_SALT_LEN];
        let salt_b = [1u8; ARGON2_SALT_LEN];
        let a = argon2id(b"password", &salt_a).unwrap();
        let b = argon2id(b"password", &salt_b).unwrap();
        assert_ne!(a, b);
    }
}

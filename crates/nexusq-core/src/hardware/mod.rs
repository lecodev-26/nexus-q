//! Hardware abstraction.
//!
//! NEXUS-Q runs on laptops, phones, servers and embedded devices. Some
//! of those have a TPM, an HSM, a Secure Element or a RISC-V root of
//! trust; most do not. This module defines the traits that hide that
//! difference behind a stable interface, plus a software backend that
//! provides working implementations on general-purpose machines.
//!
//! ## Traits
//!
//! - [`RandomSource`] — cryptographic randomness. Re-exported from
//!   [`crate::crypto::random`] so all backends live under one roof.
//! - [`SecureStorage`] — persistent, tamper-resistant byte storage.
//! - [`KeyProvider`] — generate and use keys that live outside the
//!   vault's own memory.
//! - [`AttestationProvider`] — prove which software is running.
//! - [`SecureMemory`] — memory that resists swapping and inspection.
//!
//! ## Backends
//!
//! A backend groups one implementation of each trait. The
//! [`SoftwareBackend`] is the default: it uses ordinary OS facilities
//! and works everywhere. Hardware backends (TPM, HSM, SE, enclave)
//! override specific traits when their platform provides the
//! corresponding capability.
//!
//! See `docs/ARCHITECTURE.md` §6.

pub mod attestation;
pub mod backend;
pub mod key_provider;
pub mod secure_memory;
pub mod secure_storage;
pub mod trng;

pub mod backends;

pub use attestation::{AttestationProvider, AttestationReport, Measurement};
pub use backend::Backend;
pub use backends::software::SoftwareBackend;
pub use key_provider::{KeyProvider, KeySpec};
pub use secure_memory::{SecureBuffer, SecureMemory};
pub use secure_storage::SecureStorage;
pub use trng::{
    HEALTH_SAMPLE_LEN, HealthFailure, HealthStatus, MIN_DISTINCT_BYTES, SoftwareTrng, TrngSource,
    check_sample,
};

// Randomness already lives in the crypto module. Re-export here so
// callers can depend on one abstraction surface.
pub use crate::crypto::random::{OsRandomSource, RandomError, RandomSource};

use serde::{Deserialize, Serialize};

/// Errors returned by hardware backends.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HardwareError {
    /// The requested capability is not available on this platform.
    #[error("capability not available on this platform")]
    NotAvailable,

    /// The operation is not supported by the chosen backend.
    ///
    /// Distinct from `NotAvailable`: `NotAvailable` means the hardware
    /// is missing, `NotSupported` means this backend has decided not to
    /// implement the operation even though the platform could.
    #[error("operation not supported by this backend")]
    NotSupported,

    /// The requested item does not exist.
    #[error("item not found")]
    NotFound,

    /// The backend returned an error the caller cannot interpret.
    #[error("backend error: {0}")]
    Backend(String),

    /// The underlying operating system call failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Identifier for a handle managed by a [`KeyProvider`].
///
/// Opaque to callers; the bytes are meaningful only to the backend that
/// issued them. A handle is not a key: leaking it does not leak the
/// key, though it may allow the holder to use it through the backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyHandle(Vec<u8>);

impl KeyHandle {
    /// Wraps a backend-specific byte sequence as a handle.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of the handle.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the handle, returning its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Identifier for an entry in a [`SecureStorage`].
///
/// Also opaque. `StorageKey` values are chosen by the caller; the
/// backend merely persists them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StorageKey(String);

impl StorageKey {
    /// Creates a storage key from a string.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the storage key as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_handle_roundtrips_through_bytes() {
        let h = KeyHandle::from_bytes(vec![1, 2, 3]);
        assert_eq!(h.as_bytes(), &[1, 2, 3]);
        let bytes = h.into_bytes();
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn storage_key_exposes_its_name() {
        let k = StorageKey::new("vault-master");
        assert_eq!(k.as_str(), "vault-master");
    }

    #[test]
    fn hardware_error_display_is_stable() {
        assert_eq!(
            HardwareError::NotAvailable.to_string(),
            "capability not available on this platform"
        );
        assert_eq!(
            HardwareError::Backend("tpm busy".into()).to_string(),
            "backend error: tpm busy"
        );
    }
}

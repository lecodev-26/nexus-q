//! Hardware-backed keys.
//!
//! A [`KeyProvider`] manages keys that never leave the backend. In
//! software it is a stub: the vault already stores keys, and a pure
//! software process has no way to protect material from itself. On a
//! TPM, HSM or Secure Element it generates keys in hardware, signs
//! with them, and returns handles instead of material.
//!
//! See `docs/ARCHITECTURE.md` §6.3.

use crate::crypto::sign::Signature;

use super::{HardwareError, KeyHandle};

/// The kind of key a provider should create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySpec {
    /// Ed25519 signing key.
    Ed25519Sign,
    /// AEAD key for symmetric encryption.
    Aead,
    /// ML-KEM key pair.
    MlKem768,
}

/// Operations on hardware-backed keys.
pub trait KeyProvider: Send + Sync {
    /// Generates a key with the given specification.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotSupported`] if the backend cannot
    /// create this kind of key, or another hardware error if
    /// generation fails.
    fn generate(&self, spec: KeySpec) -> Result<KeyHandle, HardwareError>;

    /// Signs `message` with the key behind `handle`.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotFound`] if the handle is unknown,
    /// [`HardwareError::NotSupported`] if the backend cannot sign, or
    /// another hardware error if signing fails.
    fn sign(&self, handle: &KeyHandle, message: &[u8]) -> Result<Signature, HardwareError>;

    /// Returns the public half of a key, if the backend can export it.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotFound`] if the handle is unknown, or
    /// [`HardwareError::NotSupported`] if the backend refuses to export
    /// public material.
    fn public_key(&self, handle: &KeyHandle) -> Result<Vec<u8>, HardwareError>;

    /// Destroys the key behind `handle`.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotFound`] if the handle is unknown, or
    /// another hardware error if destruction fails.
    fn destroy(&self, handle: &KeyHandle) -> Result<(), HardwareError>;
}

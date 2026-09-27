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

/// Evidence that a key lives in hardware.
///
/// The signature is produced by the hardware itself over the public
/// key plus the nonce. A verifier who trusts the hardware vendor's
/// root key can check that:
///
/// 1. The public key was generated inside the chip.
/// 2. The chip was asked to prove it just now (nonce freshness).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAttestation {
    /// The public half of the attested key.
    pub public_key: Vec<u8>,

    /// Signature over `public_key || nonce`, produced by the chip.
    pub signature: Vec<u8>,

    /// The nonce that was provided in the request, echoed back.
    pub nonce: Option<Vec<u8>>,
}

/// Metadata about a hardware-backed key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The specification the key was created from.
    pub spec: KeySpec,

    /// The public half, if the key has one and it is exportable.
    pub public_key: Option<Vec<u8>>,

    /// Whether the private half can be exported from the backend.
    ///
    /// Most hardware key stores refuse this; the flag exists so that
    /// callers can refuse to use a key that can leave its protection.
    pub exportable: bool,
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

    /// Asks the backend to prove that `handle` refers to a key that
    /// lives inside the hardware.
    ///
    /// The nonce, if present, must be echoed back in the attestation
    /// so the verifier can bind it to a live challenge.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotFound`] if the handle is unknown,
    /// [`HardwareError::NotSupported`] if the backend cannot attest
    /// keys, or another hardware error if the operation fails.
    fn attest_key(
        &self,
        handle: &KeyHandle,
        nonce: Option<&[u8]>,
    ) -> Result<KeyAttestation, HardwareError>;

    /// Returns metadata about a hardware-backed key.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotFound`] if the handle is unknown, or
    /// another hardware error if the read fails.
    fn key_info(&self, handle: &KeyHandle) -> Result<KeyInfo, HardwareError>;
}

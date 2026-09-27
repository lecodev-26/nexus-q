//! Persistent, tamper-resistant byte storage.
//!
//! A [`SecureStorage`] is a key-value store for opaque bytes. In
//! software it is a directory with strict permissions; on a real
//! platform it can be TPM NV memory, an HSM slot, or a Secure Element
//! file.
//!
//! Keys are chosen by the caller. Values are opaque to the backend;
//! encryption, if any, is the caller's concern.
//!
//! See `docs/ARCHITECTURE.md` §6.2.

use super::{HardwareError, StorageKey};

/// A persistent key-value store for sensitive bytes.
pub trait SecureStorage: Send + Sync {
    /// Reads the value stored under `key`.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotFound`] if the key is absent, or
    /// another hardware error if the read fails.
    fn read(&self, key: &StorageKey) -> Result<Vec<u8>, HardwareError>;

    /// Writes `value` under `key`, replacing any previous value.
    ///
    /// # Errors
    ///
    /// Returns a hardware error if the write fails.
    fn write(&self, key: &StorageKey, value: &[u8]) -> Result<(), HardwareError>;

    /// Deletes `key`.
    ///
    /// Deleting a missing key is not an error: the operation is
    /// idempotent, matching typical filesystem semantics.
    ///
    /// # Errors
    ///
    /// Returns a hardware error if the delete fails for a reason other
    /// than absence.
    fn delete(&self, key: &StorageKey) -> Result<(), HardwareError>;

    /// Returns `true` if `key` exists.
    ///
    /// # Errors
    ///
    /// Returns a hardware error if the check cannot be performed.
    fn exists(&self, key: &StorageKey) -> Result<bool, HardwareError>;

    /// Lists every key whose name starts with `prefix`.
    ///
    /// # Errors
    ///
    /// Returns a hardware error if the enumeration fails.
    fn list(&self, prefix: &str) -> Result<Vec<StorageKey>, HardwareError>;
}

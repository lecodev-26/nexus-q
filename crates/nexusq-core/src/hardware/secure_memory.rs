//! Secure memory.
//!
//! A [`SecureMemory`] allocates buffers that resist swapping and, where
//! the platform allows, inspection. On Linux and Android this means
//! `mlock`; on platforms without such a facility the operation is a
//! no-op that still returns a usable buffer.
//!
//! NEXUS-Q never relies on secure memory for correctness. Secrets are
//! zeroized on drop regardless of whether they were locked. Locking is
//! a defense in depth.
//!
//! See `docs/ARCHITECTURE.md` §6.5 and `docs/THREAT_MODEL.md` §O-03.

use zeroize::Zeroizing;

use super::HardwareError;

/// A buffer whose contents are zeroized on drop.
///
/// On backends that support it, the buffer is also locked in memory so
/// it cannot be swapped to disk.
#[derive(Debug)]
pub struct SecureBuffer {
    inner: Zeroizing<Vec<u8>>,
    locked: bool,
}

impl SecureBuffer {
    /// Wraps `bytes` in a secure buffer.
    ///
    /// This constructor does not lock the buffer; callers should use
    /// [`SecureMemory::lock`] after allocation.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Zeroizing::new(bytes),
            locked: false,
        }
    }

    /// Returns the bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Returns the bytes mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Returns `true` if the buffer is marked as locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Records that the buffer is locked.
    ///
    /// This method does not actually lock anything; the backend that
    /// creates the buffer is responsible for the actual `mlock`. It
    /// exists so the flag can be set by trusted code without exposing
    /// the field.
    pub(crate) fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
    }
}

/// Operations for allocating and locking secret memory.
pub trait SecureMemory: Send + Sync {
    /// Allocates a buffer of `len` zeroed bytes.
    ///
    /// # Errors
    ///
    /// Returns a hardware error if allocation fails.
    fn alloc(&self, len: usize) -> Result<SecureBuffer, HardwareError>;

    /// Attempts to lock `buffer` in memory.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotSupported`] if the backend cannot
    /// lock memory. In that case the buffer remains usable; the caller
    /// decides whether to treat the failure as fatal.
    fn lock(&self, buffer: &mut SecureBuffer) -> Result<(), HardwareError>;

    /// Unlocks a previously locked buffer.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotSupported`] if the backend cannot
    /// unlock memory, or another hardware error if the operation fails.
    fn unlock(&self, buffer: &mut SecureBuffer) -> Result<(), HardwareError>;
}

//! Randomness abstraction.
//!
//! All key material, nonces and salts in NEXUS-Q come from a
//! [`RandomSource`]. The default source is the operating system CSPRNG
//! via [`OsRandomSource`]. Hardware sources (TRNG) plug in later through
//! the same trait.

use rand_core::{OsRng, TryRngCore};

/// Errors returned by a [`RandomSource`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RandomError {
    /// The operating system reported a failure while collecting entropy.
    #[error("operating system RNG failed")]
    OsFailure,

    /// The source is temporarily unable to produce random bytes.
    #[error("random source temporarily unavailable")]
    Unavailable,
}

/// A source of cryptographically secure random bytes.
///
/// Implementations must guarantee that the bytes returned are
/// indistinguishable from uniform random to any computationally bounded
/// adversary, and that concurrent calls do not repeat output.
pub trait RandomSource: Send + Sync {
    /// Fills `dest` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the source cannot produce entropy. Callers
    /// must treat any error as fatal for the operation in progress: it is
    /// never acceptable to fall back to a weaker source without an
    /// explicit policy decision.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandomError>;

    /// Returns a `Vec` of `len` random bytes.
    ///
    /// Convenience wrapper over [`fill_bytes`](Self::fill_bytes).
    fn bytes(&mut self, len: usize) -> Result<Vec<u8>, RandomError> {
        let mut buf = vec![0u8; len];
        self.fill_bytes(&mut buf)?;
        Ok(buf)
    }
}

/// Default [`RandomSource`] backed by the operating system CSPRNG.
///
/// On Linux and Android this uses `getrandom(2)`. On other platforms it
/// uses whatever `rand_core::OsRng` provides. The OS guarantees that the
/// source blocks (or fails) until sufficient entropy is available during
/// boot, and never returns predictable output afterward.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandomSource;

impl OsRandomSource {
    /// Creates a new source. Cheap; the OS RNG is a global resource.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RandomSource for OsRandomSource {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandomError> {
        OsRng
            .try_fill_bytes(dest)
            .map_err(|_| RandomError::OsFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_requested_length() {
        let mut src = OsRandomSource::new();
        let buf = src.bytes(64).expect("os rng available");
        assert_eq!(buf.len(), 64);
    }

    #[test]
    fn produces_different_output_on_successive_calls() {
        let mut src = OsRandomSource::new();
        let a = src.bytes(32).expect("os rng available");
        let b = src.bytes(32).expect("os rng available");
        assert_ne!(a, b, "two 32-byte draws should not collide");
    }

    #[test]
    fn zero_length_is_allowed() {
        let mut src = OsRandomSource::new();
        let buf = src.bytes(0).expect("os rng available");
        assert!(buf.is_empty());
    }
}

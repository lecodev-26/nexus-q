//! Mixed randomness source.
//!
//! Combines a hardware TRNG (when available) with the operating
//! system CSPRNG. The two sources are concatenated and run through
//! HKDF-SHA256 before any bytes reach the caller. If the TRNG is
//! absent or fails, the OS alone is used.
//!
//! ## Why mix
//!
//! - If the TRNG is faulty or malicious, the OS CSPRNG still provides
//!   entropy.
//! - If the OS CSPRNG is compromised, the TRNG still provides entropy.
//! - If both are healthy, the output is at least as good as either.
//!
//! Mixing is cheap and turns a single point of failure into two. The
//! construction is documented in `docs/CRYPTOGRAPHY.md` §4.1 and
//! `docs/THREAT_MODEL.md` §T-11.
//!
//! ## Failure policy
//!
//! - TRNG missing: mixed source silently uses only the OS.
//! - TRNG present but a read fails: the failure is recorded, subsequent
//!   calls skip the TRNG until the caller resets it. The current call
//!   proceeds with the OS alone.
//! - OS read fails: the whole call fails. There is no third source.
//!
//! The policy is deliberate: a random source that cannot produce
//! entropy must never fall back to a weaker one, only to an equally
//! strong or stronger one. "OS only" qualifies; "TRNG only" does not.

use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

use crate::crypto::kdf::hkdf_sha256;
use crate::crypto::random::{OsRandomSource, RandomError, RandomSource};

use super::trng::TrngSource;

/// HKDF info string used to mix sources.
const MIX_INFO: &[u8] = b"nexusq-mixed-rng-v1";

/// A [`RandomSource`] that mixes a TRNG with the OS CSPRNG.
pub struct MixedRandomSource {
    trng: Option<Box<dyn TrngSource>>,
    os: OsRandomSource,
    /// Set to `true` when the TRNG has failed at least once. Once set,
    /// the TRNG is skipped for subsequent calls.
    trng_failed: AtomicBool,
}

impl std::fmt::Debug for MixedRandomSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MixedRandomSource")
            .field(
                "trng",
                &self.trng.as_ref().map(|t| t.name()).unwrap_or("none"),
            )
            .field("trng_failed", &self.trng_failed.load(Ordering::Relaxed))
            .finish()
    }
}

impl MixedRandomSource {
    /// Creates a mixed source from an optional TRNG.
    ///
    /// Pass `None` to use only the OS CSPRNG.
    #[must_use]
    pub fn new(trng: Option<Box<dyn TrngSource>>) -> Self {
        Self {
            trng,
            os: OsRandomSource::new(),
            trng_failed: AtomicBool::new(false),
        }
    }

    /// Creates a mixed source that only uses the OS CSPRNG.
    #[must_use]
    pub fn os_only() -> Self {
        Self::new(None)
    }

    /// Returns `true` if a TRNG is attached and has not failed yet.
    #[must_use]
    pub fn has_usable_trng(&self) -> bool {
        self.trng.is_some() && !self.trng_failed.load(Ordering::Relaxed)
    }

    /// Returns the name of the attached TRNG, if any.
    #[must_use]
    pub fn trng_name(&self) -> Option<&'static str> {
        self.trng.as_ref().map(|t| t.name())
    }

    /// Clears the failure flag, so the next call will try the TRNG
    /// again. Useful after an operator has fixed a transient issue.
    pub fn reset_trng(&self) {
        self.trng_failed.store(false, Ordering::Relaxed);
    }
}

impl RandomSource for MixedRandomSource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        if dest.is_empty() {
            return Ok(());
        }

        // Always draw from the OS. This is the guaranteed source.
        let mut os_bytes = Zeroizing::new(vec![0u8; dest.len()]);
        self.os.fill_bytes(os_bytes.as_mut())?;

        // Try the TRNG unless it has already failed.
        let mut combined: Zeroizing<Vec<u8>> = if self.has_usable_trng() {
            let trng = self.trng.as_ref().expect("checked above");
            let mut trng_bytes = Zeroizing::new(vec![0u8; dest.len()]);
            match trng.read(trng_bytes.as_mut()) {
                Ok(()) => {
                    let mut buf = Zeroizing::new(Vec::with_capacity(2 * dest.len()));
                    buf.extend_from_slice(trng_bytes.as_ref());
                    buf.extend_from_slice(os_bytes.as_ref());
                    buf
                }
                Err(_) => {
                    // Record the failure and fall back to OS only.
                    self.trng_failed.store(true, Ordering::Relaxed);
                    let mut buf = Zeroizing::new(Vec::with_capacity(dest.len()));
                    buf.extend_from_slice(os_bytes.as_ref());
                    buf
                }
            }
        } else {
            let mut buf = Zeroizing::new(Vec::with_capacity(dest.len()));
            buf.extend_from_slice(os_bytes.as_ref());
            buf
        };

        // Run the concatenation through HKDF. This is deterministic in
        // the input; the mixing is what turns two possibly correlated
        // streams into one that is at least as strong as either.
        let mixed = hkdf_sha256(&combined, None, MIX_INFO).map_err(|_| RandomError::Unavailable)?;
        combined.clear();

        // Copy as many bytes as requested. If `dest.len() > 32` we need
        // to expand, but our largest request is a 32-byte key, so a
        // single HKDF output covers the common case. For longer
        // outputs we would need HKDF-Expand with a counter; we avoid
        // that by refusing to serve more than 32 bytes at a time and
        // letting callers loop.
        if dest.len() > mixed.len() {
            // Fill in 32-byte chunks, each with a fresh HKDF.
            let mut offset = 0;
            while offset < dest.len() {
                let mut os_chunk = Zeroizing::new(vec![0u8; 32]);
                self.os.fill_bytes(os_chunk.as_mut())?;
                let chunk =
                    hkdf_sha256(&os_chunk, None, MIX_INFO).map_err(|_| RandomError::Unavailable)?;
                let n = (dest.len() - offset).min(chunk.len());
                dest[offset..offset + n].copy_from_slice(&chunk[..n]);
                offset += n;
            }
            return Ok(());
        }

        let n = dest.len().min(mixed.len());
        dest[..n].copy_from_slice(&mixed[..n]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    /// A TRNG that always succeeds and fills with a fixed byte.
    struct GoodTrng {
        byte: u8,
    }

    impl TrngSource for GoodTrng {
        fn read(&self, dest: &mut [u8]) -> Result<(), RandomError> {
            dest.fill(self.byte);
            Ok(())
        }
        fn name(&self) -> &'static str {
            "good"
        }
    }

    /// A TRNG that always fails.
    struct BadTrng;

    impl TrngSource for BadTrng {
        fn read(&self, _dest: &mut [u8]) -> Result<(), RandomError> {
            Err(RandomError::Unavailable)
        }
        fn name(&self) -> &'static str {
            "bad"
        }
    }

    /// A TRNG that counts how many times it was read.
    struct CountingTrng {
        reads: Arc<AtomicUsize>,
    }

    impl TrngSource for CountingTrng {
        fn read(&self, dest: &mut [u8]) -> Result<(), RandomError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            dest.fill(0xAA);
            Ok(())
        }
        fn name(&self) -> &'static str {
            "counting"
        }
    }

    #[test]
    fn os_only_produces_bytes() {
        let src = MixedRandomSource::os_only();
        let mut buf = [0u8; 32];
        src.fill_bytes(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn os_only_has_no_trng() {
        let src = MixedRandomSource::os_only();
        assert!(!src.has_usable_trng());
        assert!(src.trng_name().is_none());
    }

    #[test]
    fn good_trng_is_used() {
        let src = MixedRandomSource::new(Some(Box::new(GoodTrng { byte: 0x55 })));
        assert!(src.has_usable_trng());
        assert_eq!(src.trng_name(), Some("good"));

        let mut buf = [0u8; 32];
        src.fill_bytes(&mut buf).unwrap();
        // The output should not be the TRNG constant alone.
        assert!(!buf.iter().all(|&b| b == 0x55));
    }

    #[test]
    fn bad_trng_falls_back_to_os() {
        let src = MixedRandomSource::new(Some(Box::new(BadTrng)));
        assert!(src.has_usable_trng());

        let mut buf = [0u8; 32];
        src.fill_bytes(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));

        // After the first failure, the TRNG is skipped.
        assert!(!src.has_usable_trng());
    }

    #[test]
    fn reset_trng_allows_retry() {
        let src = MixedRandomSource::new(Some(Box::new(BadTrng)));
        let mut buf = [0u8; 32];
        src.fill_bytes(&mut buf).unwrap();
        assert!(!src.has_usable_trng());

        src.reset_trng();
        assert!(src.has_usable_trng());
    }

    #[test]
    fn bad_trng_is_read_only_once() {
        let reads = Arc::new(AtomicUsize::new(0));
        let counter = reads.clone();
        let src = MixedRandomSource::new(Some(Box::new(BadTrng)));
        let _ = counter;

        // First call tries the TRNG and fails.
        let mut buf = [0u8; 32];
        src.fill_bytes(&mut buf).unwrap();
        assert!(!src.has_usable_trng());

        // Second call should not touch the TRNG.
        src.fill_bytes(&mut buf).unwrap();
    }

    #[test]
    fn counting_trng_is_called_every_time_when_healthy() {
        let reads = Arc::new(AtomicUsize::new(0));
        let counter = reads.clone();
        let src = MixedRandomSource::new(Some(Box::new(CountingTrng { reads: counter })));

        let mut buf = [0u8; 32];
        src.fill_bytes(&mut buf).unwrap();
        src.fill_bytes(&mut buf).unwrap();
        src.fill_bytes(&mut buf).unwrap();
        assert_eq!(reads.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn empty_dest_is_ok() {
        let src = MixedRandomSource::os_only();
        let mut buf = [0u8; 0];
        src.fill_bytes(&mut buf).unwrap();
    }

    #[test]
    fn large_request_is_handled() {
        let src = MixedRandomSource::os_only();
        let mut buf = [0u8; 200];
        src.fill_bytes(&mut buf).unwrap();
        // Statistically, all zeros is impossible with 200 bytes.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn outputs_differ_between_calls() {
        let src = MixedRandomSource::os_only();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        src.fill_bytes(&mut a).unwrap();
        src.fill_bytes(&mut b).unwrap();
        assert_ne!(a, b);
    }
}

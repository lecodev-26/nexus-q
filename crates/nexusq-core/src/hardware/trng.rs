//! True Random Number Generators and health checks.
//!
//! A TRNG harvests entropy from physical phenomena: thermal noise,
//! clock jitter, radioactive decay, ring oscillator drift. It is the
//! only source of randomness that is not derived from a seed.
//!
//! NEXUS-Q does not trust a TRNG by itself. Every reading goes through
//! a health check, and every produced byte string is mixed with the OS
//! CSPRNG before use. If the TRNG is absent, faulty, or temporarily
//! unavailable, the software silently falls back to the OS source; the
//! fallback is documented in `docs/THREAT_MODEL.md`.
//!
//! ## What we do not do
//!
//! The health checks here are **not** NIST SP 800-90B compliant. They
//! catch obviously broken sources (all zeros, repeating patterns,
//! insufficient byte diversity) so that a failed TRNG does not
//! silently feed predictable bytes into a key. A production
//! deployment that relies on a TRNG for regulatory compliance must
//! run the full AIS 31 / SP 800-90B test suite on the actual hardware.
//!
//! See `docs/ARCHITECTURE.md` §6 and `docs/CRYPTOGRAPHY.md` §4.1.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::random::RandomError;

/// Number of bytes drawn per health check sample.
pub const HEALTH_SAMPLE_LEN: usize = 64;

/// Minimum number of distinct byte values a healthy sample must
/// contain.
///
/// A uniform 64-byte sample has around 58 distinct values on average
/// (birthday-paradox estimate). A source that returns far fewer is
/// producing a very narrow distribution: for example, all zeros or a
/// single repeated byte.
pub const MIN_DISTINCT_BYTES: usize = 16;

/// Result of a health check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// The source produced a sample that passed every check.
    Healthy,

    /// The source produced a sample but one or more checks failed.
    /// The source should not be used until it recovers.
    Degraded {
        /// The check that failed first.
        reason: HealthFailure,
    },

    /// The source could not produce a sample at all.
    Unavailable {
        /// Why the sample could not be taken.
        reason: String,
    },
}

impl HealthStatus {
    /// Returns `true` for [`HealthStatus::Healthy`].
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Returns `true` for [`HealthStatus::Unavailable`].
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }
}

/// The specific check that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthFailure {
    /// The sample was not the expected length.
    WrongLength,

    /// All bytes in the sample were identical.
    ConstantOutput,

    /// The sample contained too few distinct byte values.
    LowDiversity,

    /// Two consecutive samples were identical.
    Repetition,
}

impl HealthFailure {
    /// Returns a short, stable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongLength => "wrong_length",
            Self::ConstantOutput => "constant_output",
            Self::LowDiversity => "low_diversity",
            Self::Repetition => "repetition",
        }
    }
}

/// Runs the health checks over a single sample.
///
/// `previous` is an optional previous sample, used for the repetition
/// check. Pass `None` for the first sample after startup.
#[must_use]
pub fn check_sample(sample: &[u8], previous: Option<&[u8]>) -> HealthStatus {
    if sample.len() != HEALTH_SAMPLE_LEN {
        return HealthStatus::Degraded {
            reason: HealthFailure::WrongLength,
        };
    }

    // Constant output: every byte identical.
    let first = sample[0];
    if sample.iter().all(|&b| b == first) {
        return HealthStatus::Degraded {
            reason: HealthFailure::ConstantOutput,
        };
    }

    // Low diversity: too few distinct values.
    let distinct: HashSet<u8> = sample.iter().copied().collect();
    if distinct.len() < MIN_DISTINCT_BYTES {
        return HealthStatus::Degraded {
            reason: HealthFailure::LowDiversity,
        };
    }

    // Repetition: identical to the previous sample.
    if let Some(prev) = previous {
        if prev == sample {
            return HealthStatus::Degraded {
                reason: HealthFailure::Repetition,
            };
        }
    }

    HealthStatus::Healthy
}

/// A source of raw hardware entropy.
///
/// Implementations are platform-specific. On a general-purpose OS the
/// typical implementation opens `/dev/hwrng` on Linux or an equivalent
/// device node, but this trait does not assume any particular path.
///
/// Implementations must be cheap to call: the TRNG is read once per
/// health check interval, not on every random draw.
pub trait TrngSource: Send + Sync {
    /// Reads `dest.len()` bytes of raw hardware entropy.
    ///
    /// # Errors
    ///
    /// Returns a [`RandomError`] if the underlying device fails or is
    /// unavailable.
    fn read(&self, dest: &mut [u8]) -> Result<(), RandomError>;

    /// Returns a human-readable name for diagnostics.
    fn name(&self) -> &'static str;
}

/// A [`TrngSource`] that is not actually backed by hardware.
///
/// On platforms without an accessible TRNG — including any Termux
/// deployment without root, and any general-purpose PC without
/// privileges on `/dev/hwrng` — this is the source returned by
/// [`SoftwareTrng::try_open`]. It fails every read, which the mixing
/// layer interprets as "no TRNG here".
#[derive(Debug, Default, Clone, Copy)]
pub struct SoftwareTrng;

impl SoftwareTrng {
    /// Attempts to open a hardware TRNG.
    ///
    /// Always returns `None` on this build: we do not depend on any
    /// platform-specific device path, and a general-purpose build
    /// cannot assume one exists. A future platform-specific backend
    /// will override this.
    #[must_use]
    pub const fn try_open() -> Option<Self> {
        None
    }
}

impl TrngSource for SoftwareTrng {
    fn read(&self, _dest: &mut [u8]) -> Result<(), RandomError> {
        Err(RandomError::Unavailable)
    }

    fn name(&self) -> &'static str {
        "software-trng-stub"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic source used by tests. Not for production.
    struct FakeTrng {
        byte: u8,
    }

    impl TrngSource for FakeTrng {
        fn read(&self, dest: &mut [u8]) -> Result<(), RandomError> {
            dest.fill(self.byte);
            Ok(())
        }

        fn name(&self) -> &'static str {
            "fake"
        }
    }

    fn healthy_sample() -> Vec<u8> {
        // 64 distinct values, well above MIN_DISTINCT_BYTES.
        (0u8..64).collect()
    }

    #[test]
    fn healthy_sample_passes() {
        assert!(check_sample(&healthy_sample(), None).is_healthy());
    }

    #[test]
    fn wrong_length_fails() {
        let short = vec![0u8; 32];
        let status = check_sample(&short, None);
        assert!(matches!(
            status,
            HealthStatus::Degraded {
                reason: HealthFailure::WrongLength
            }
        ));
    }

    #[test]
    fn constant_output_fails() {
        let all_zeros = vec![0u8; HEALTH_SAMPLE_LEN];
        let status = check_sample(&all_zeros, None);
        assert!(matches!(
            status,
            HealthStatus::Degraded {
                reason: HealthFailure::ConstantOutput
            }
        ));
    }

    #[test]
    fn low_diversity_fails() {
        // 64 bytes, but only 4 distinct values.
        let mut sample = Vec::with_capacity(HEALTH_SAMPLE_LEN);
        for i in 0..HEALTH_SAMPLE_LEN {
            sample.push((i % 4) as u8);
        }
        let status = check_sample(&sample, None);
        assert!(matches!(
            status,
            HealthStatus::Degraded {
                reason: HealthFailure::LowDiversity
            }
        ));
    }

    #[test]
    fn repetition_fails() {
        let sample = healthy_sample();
        let status = check_sample(&sample, Some(&sample));
        assert!(matches!(
            status,
            HealthStatus::Degraded {
                reason: HealthFailure::Repetition
            }
        ));
    }

    #[test]
    fn different_from_previous_passes() {
        let a = healthy_sample();
        let b: Vec<u8> = (64u8..128).collect();
        assert!(check_sample(&b, Some(&a)).is_healthy());
    }

    #[test]
    fn health_status_helpers() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(!HealthStatus::Healthy.is_unavailable());
        let unavail = HealthStatus::Unavailable {
            reason: "no device".into(),
        };
        assert!(!unavail.is_healthy());
        assert!(unavail.is_unavailable());
    }

    #[test]
    fn health_failure_strings_are_stable() {
        assert_eq!(HealthFailure::WrongLength.as_str(), "wrong_length");
        assert_eq!(HealthFailure::ConstantOutput.as_str(), "constant_output");
        assert_eq!(HealthFailure::LowDiversity.as_str(), "low_diversity");
        assert_eq!(HealthFailure::Repetition.as_str(), "repetition");
    }

    #[test]
    fn software_trng_reports_none() {
        assert!(SoftwareTrng::try_open().is_none());
    }

    #[test]
    fn software_trng_read_fails() {
        let trng = SoftwareTrng;
        let mut buf = [0u8; 8];
        assert!(trng.read(&mut buf).is_err());
    }

    #[test]
    fn fake_trng_fills_buffer() {
        let trng = FakeTrng { byte: 0xAB };
        let mut buf = [0u8; 8];
        trng.read(&mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAB));
    }
}

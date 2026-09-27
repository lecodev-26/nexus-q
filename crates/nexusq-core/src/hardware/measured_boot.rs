//! Measured boot.
//!
//! Measured boot records a digest of every component that runs during
//! startup, in a register that cannot be rewritten afterwards. The
//! records are not policed: a component is measured whether or not it
//! is signed. The point is evidence, not enforcement.
//!
//! ## PCRs
//!
//! On TPM 2.0 the registers are called Platform Configuration
//! Registers (PCRs). The term is used here even on other platforms,
//! because every implementation we expect to write models the same
//! idea. The trait does not assume a TPM: `pcrs()` returns whatever
//! the platform exposes, keyed by index.
//!
//! ## Relation to secure boot
//!
//! `SecureBoot` answers "can this platform prove its boot chain is
//! trusted". `MeasuredBoot` answers "what exactly did this platform
//! run". Attestation uses the second: a remote verifier asks for the
//! PCRs, checks them against a known-good reference, and decides
//! whether to trust the device.
//!
//! See `docs/SECURE_BOOT.md` and `docs/ARCHITECTURE.md` §2.3.

use serde::{Deserialize, Serialize};

use super::HardwareError;

/// Hash algorithm used to produce a register value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterAlgorithm {
    /// SHA-256, 32-byte digests. The TPM 2.0 default.
    #[serde(rename = "sha256")]
    Sha256,
    /// SHA-384, 48-byte digests. Used by some TPM 2.0 configurations.
    #[serde(rename = "sha384")]
    Sha384,
}

impl RegisterAlgorithm {
    /// Returns the canonical lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
        }
    }

    /// Returns the digest length in bytes for this algorithm.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

/// One register and its current value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    /// Index of the register (0-based).
    pub index: u32,

    /// Which hash produced `value`.
    pub algorithm: RegisterAlgorithm,

    /// The digest itself. Length must match `algorithm.digest_len()`.
    pub value: Vec<u8>,
}

impl Register {
    /// Returns `true` if the value length matches the declared
    /// algorithm.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.value.len() == self.algorithm.digest_len()
    }
}

/// A platform that records boot measurements.
pub trait MeasuredBoot: Send + Sync {
    /// Returns the current value of every register the platform
    /// exposes.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotAvailable`] if the platform has no
    /// measurement facility, or another hardware error if the read
    /// fails.
    fn registers(&self) -> Result<Vec<Register>, HardwareError>;

    /// Reads a specific register by index.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotFound`] if the index does not
    /// exist, [`HardwareError::NotAvailable`] if the platform has no
    /// measurement facility, or another hardware error if the read
    /// fails.
    fn register(&self, index: u32) -> Result<Register, HardwareError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_strings_are_stable() {
        assert_eq!(RegisterAlgorithm::Sha256.as_str(), "sha256");
        assert_eq!(RegisterAlgorithm::Sha384.as_str(), "sha384");
    }

    #[test]
    fn digest_lengths_match_the_algorithms() {
        assert_eq!(RegisterAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(RegisterAlgorithm::Sha384.digest_len(), 48);
    }

    #[test]
    fn register_is_consistent_when_length_matches() {
        let r = Register {
            index: 0,
            algorithm: RegisterAlgorithm::Sha256,
            value: vec![0u8; 32],
        };
        assert!(r.is_consistent());
    }

    #[test]
    fn register_is_inconsistent_when_length_differs() {
        let r = Register {
            index: 0,
            algorithm: RegisterAlgorithm::Sha256,
            value: vec![0u8; 48],
        };
        assert!(!r.is_consistent());
    }

    #[test]
    fn register_is_cloneable_and_eq() {
        let r = Register {
            index: 7,
            algorithm: RegisterAlgorithm::Sha384,
            value: vec![0xAB; 48],
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }
}

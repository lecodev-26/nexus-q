//! Secure boot state.
//!
//! Secure boot is a chain of signed components. Each link verifies the
//! signature of the next before handing over control:
//!
//! ```text
//! Boot ROM (immutable)
//!     verifies ->
//! Bootloader
//!     verifies ->
//! Kernel
//!     verifies ->
//! Initramfs / rootfs
//!     verifies ->
//! NEXUS-Q
//! ```
//!
//! NEXUS-Q cannot inspect the boot chain from user space on a
//! general-purpose operating system. What it can do is ask the
//! platform, through a [`SecureBoot`] implementation, what it knows.
//! The answer is either "the chain verified and here is the evidence"
//! or "I cannot tell".
//!
//! This is deliberately conservative: [`SecureBootState::Unknown`] is
//! the correct answer when the platform cannot prove otherwise, and
//! `Unknown` must never be treated as `Verified`.
//!
//! See `docs/ARCHITECTURE.md` §2.3 and `docs/SECURE_BOOT.md`.

use serde::{Deserialize, Serialize};

/// Where the chain of trust starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootOfTrust {
    /// Immutable ROM burned into the SoC at manufacture.
    BootRom,
    /// Trusted Platform Module.
    Tpm,
    /// Secure Element (for example, a dedicated security chip).
    SecureElement,
    /// No root of trust available on this platform.
    None,
}

impl RootOfTrust {
    /// Returns the canonical lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BootRom => "boot_rom",
            Self::Tpm => "tpm",
            Self::SecureElement => "secure_element",
            Self::None => "none",
        }
    }

    /// Returns `true` if this root of trust can actually anchor a
    /// chain of signatures.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// A component that was executed during boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootComponent {
    /// Human-readable name (e.g., "bootloader", "kernel", "nexusq").
    pub name: String,

    /// Digest of the component's bytes, as reported by the platform.
    pub measurement: Vec<u8>,

    /// Whether the platform reports this component as verified.
    pub verified: bool,
}

/// What NEXUS-Q knows about the boot chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureBootState {
    /// The platform cannot tell us anything. This is the correct
    /// answer on any general-purpose OS and must never be treated as
    /// `Verified`.
    Unknown,

    /// The chain verified end to end. The root of trust and the list
    /// of measured components are included.
    Verified {
        /// Where the chain starts.
        root_of_trust: RootOfTrust,
        /// Every component that was part of the chain.
        components: Vec<BootComponent>,
    },

    /// The chain exists but a link was not verified. NEXUS-Q
    /// continues, but callers who require secure boot must refuse to
    /// operate.
    Unverified {
        /// Why the platform reports an unverified boot.
        reason: String,
    },

    /// The chain exists and a link failed verification. This is a
    /// stronger statement than `Unverified`: something was tampered
    /// with.
    Failed {
        /// Why the platform reports a failure.
        reason: String,
    },
}

impl SecureBootState {
    /// Returns `true` only for [`SecureBootState::Verified`].
    ///
    /// Do not use this to decide whether to trust the current process
    /// in a security-critical path without a fallback. A `false`
    /// answer does not mean the system is compromised; it means the
    /// platform cannot prove it is not.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// Returns `true` for [`SecureBootState::Unknown`].
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Returns `true` for [`SecureBootState::Failed`].
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// A platform that can report its secure boot state.
pub trait SecureBoot: Send + Sync {
    /// Returns what the platform knows about the boot chain.
    ///
    /// Implementations must return [`SecureBootState::Unknown`] when
    /// they have no information, rather than guessing.
    fn state(&self) -> SecureBootState;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_of_trust_strings_are_stable() {
        assert_eq!(RootOfTrust::BootRom.as_str(), "boot_rom");
        assert_eq!(RootOfTrust::Tpm.as_str(), "tpm");
        assert_eq!(RootOfTrust::SecureElement.as_str(), "secure_element");
        assert_eq!(RootOfTrust::None.as_str(), "none");
    }

    #[test]
    fn only_none_is_unusable() {
        assert!(RootOfTrust::BootRom.is_usable());
        assert!(RootOfTrust::Tpm.is_usable());
        assert!(RootOfTrust::SecureElement.is_usable());
        assert!(!RootOfTrust::None.is_usable());
    }

    #[test]
    fn unknown_is_not_verified() {
        let s = SecureBootState::Unknown;
        assert!(!s.is_verified());
        assert!(s.is_unknown());
        assert!(!s.is_failed());
    }

    #[test]
    fn verified_is_verified() {
        let s = SecureBootState::Verified {
            root_of_trust: RootOfTrust::Tpm,
            components: vec![BootComponent {
                name: "bootloader".into(),
                measurement: vec![0xAA; 32],
                verified: true,
            }],
        };
        assert!(s.is_verified());
        assert!(!s.is_unknown());
        assert!(!s.is_failed());
    }

    #[test]
    fn unverified_is_neither_verified_nor_failed() {
        let s = SecureBootState::Unverified {
            reason: "development mode".into(),
        };
        assert!(!s.is_verified());
        assert!(!s.is_unknown());
        assert!(!s.is_failed());
    }

    #[test]
    fn failed_is_failed() {
        let s = SecureBootState::Failed {
            reason: "kernel signature mismatch".into(),
        };
        assert!(!s.is_verified());
        assert!(!s.is_unknown());
        assert!(s.is_failed());
    }

    #[test]
    fn state_is_cloneable_and_eq() {
        let s = SecureBootState::Verified {
            root_of_trust: RootOfTrust::BootRom,
            components: vec![],
        };
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn boot_component_carries_name_measurement_and_flag() {
        let c = BootComponent {
            name: "kernel".into(),
            measurement: vec![1, 2, 3],
            verified: true,
        };
        assert_eq!(c.name, "kernel");
        assert_eq!(c.measurement, vec![1, 2, 3]);
        assert!(c.verified);
    }
}

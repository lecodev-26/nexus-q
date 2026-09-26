//! Key lifecycle states.
//!
//! A key moves through a small state machine during its life. Some
//! transitions are allowed, others are not; the state is enforced by
//! [`KeyStatus::transition_to`]. See `docs/KEY_MANAGEMENT.md` §5 for
//! the rationale behind each state and transition.
//!
//! This type describes the status of a *key*. The vault has its own
//! status type with a different set of states (locked, unlocked,
//! sealed, compromised) defined in a later module.

use std::fmt;
use std::str::FromStr;

/// Lifecycle state of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyStatus {
    /// Just created, not yet used.
    ///
    /// A key in this state has not signed, encrypted or been used for
    /// key agreement. It can be activated or destroyed.
    Generated,

    /// Normal operating state.
    ///
    /// The key can be used according to its purpose.
    Active,

    /// Being replaced by a newer key.
    ///
    /// During the grace period the key still verifies signatures and
    /// decrypts data, but does not produce new signatures or new
    /// ciphertexts.
    Rotating,

    /// Superseded by a newer key.
    ///
    /// Only verification and decryption of data protected while the
    /// key was active.
    Retired,

    /// Compromised or no longer trusted.
    ///
    /// No new operations. Old data may still be decryptable if the
    /// policy allows, but new signatures and encryptions are refused.
    Revoked,

    /// Key material erased.
    ///
    /// Only the metadata record remains, for audit purposes. Data
    /// protected by this key is permanently unreadable.
    Destroyed,
}

impl KeyStatus {
    /// Returns the canonical lowercase identifier of this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generated => "generated",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
            Self::Destroyed => "destroyed",
        }
    }

    /// Returns `true` if a key in this state can be used to produce
    /// new signatures or new ciphertexts.
    #[must_use]
    pub const fn is_usable_for_new_work(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns `true` if a key in this state can still be used to
    /// verify signatures or decrypt data that was protected while the
    /// key was active.
    #[must_use]
    pub const fn is_usable_for_verification(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Rotating | Self::Retired | Self::Revoked
        )
    }

    /// Returns `true` if the key material for this status is
    /// considered gone.
    #[must_use]
    pub const fn is_material_present(self) -> bool {
        !matches!(self, Self::Destroyed)
    }

    /// Returns `true` if the transition `self -> target` is allowed.
    ///
    /// See `docs/KEY_MANAGEMENT.md` §5.2 for the rationale.
    #[must_use]
    pub const fn can_transition_to(self, target: KeyStatus) -> bool {
        use KeyStatus::{Active, Destroyed, Generated, Retired, Revoked, Rotating};

        matches!(
            (self, target),
            // Normal progression
            (Generated, Active)
                | (Active, Rotating)
                | (Rotating, Retired)
                // Compromise paths
                | (Active, Revoked)
                | (Retired, Revoked)
                | (Rotating, Revoked)
                // Destruction
                | (Generated, Destroyed)
                | (Active, Destroyed)
                | (Rotating, Destroyed)
                | (Retired, Destroyed)
                | (Revoked, Destroyed)
        )
    }

    /// Attempts to move to `target`.
    ///
    /// # Errors
    ///
    /// Returns [`StatusTransitionError`] if the transition is not
    /// allowed.
    pub fn transition_to(self, target: KeyStatus) -> Result<KeyStatus, StatusTransitionError> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(StatusTransitionError {
                from: self,
                to: target,
            })
        }
    }
}

impl fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KeyStatus {
    type Err = StatusParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "generated" => Ok(Self::Generated),
            "active" => Ok(Self::Active),
            "rotating" => Ok(Self::Rotating),
            "retired" => Ok(Self::Retired),
            "revoked" => Ok(Self::Revoked),
            "destroyed" => Ok(Self::Destroyed),
            other => Err(StatusParseError::Unknown(other.to_string())),
        }
    }
}

/// Error returned when a status transition is not allowed.
#[derive(Debug, thiserror::Error)]
#[error("invalid status transition: {from} -> {to}")]
pub struct StatusTransitionError {
    /// The state we were in.
    pub from: KeyStatus,
    /// The state we tried to reach.
    pub to: KeyStatus,
}

/// Errors returned when parsing a [`KeyStatus`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StatusParseError {
    /// The input did not match any known status identifier.
    #[error("unknown status: {0}")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_statuses_roundtrip_via_string() {
        let all = [
            KeyStatus::Generated,
            KeyStatus::Active,
            KeyStatus::Rotating,
            KeyStatus::Retired,
            KeyStatus::Revoked,
            KeyStatus::Destroyed,
        ];
        for &s in &all {
            let text = s.to_string();
            let parsed: KeyStatus = text.parse().unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn canonical_strings_are_stable() {
        assert_eq!(KeyStatus::Generated.as_str(), "generated");
        assert_eq!(KeyStatus::Active.as_str(), "active");
        assert_eq!(KeyStatus::Rotating.as_str(), "rotating");
        assert_eq!(KeyStatus::Retired.as_str(), "retired");
        assert_eq!(KeyStatus::Revoked.as_str(), "revoked");
        assert_eq!(KeyStatus::Destroyed.as_str(), "destroyed");
    }

    #[test]
    fn parse_rejects_unknown() {
        assert!(matches!(
            "expired".parse::<KeyStatus>(),
            Err(StatusParseError::Unknown(_))
        ));
    }

    #[test]
    fn parse_rejects_case_variants() {
        assert!("Active".parse::<KeyStatus>().is_err());
        assert!("ACTIVE".parse::<KeyStatus>().is_err());
    }

    #[test]
    fn normal_lifecycle_transitions_are_allowed() {
        assert!(KeyStatus::Generated.can_transition_to(KeyStatus::Active));
        assert!(KeyStatus::Active.can_transition_to(KeyStatus::Rotating));
        assert!(KeyStatus::Rotating.can_transition_to(KeyStatus::Retired));
    }

    #[test]
    fn compromise_paths_are_allowed() {
        assert!(KeyStatus::Active.can_transition_to(KeyStatus::Revoked));
        assert!(KeyStatus::Rotating.can_transition_to(KeyStatus::Revoked));
        assert!(KeyStatus::Retired.can_transition_to(KeyStatus::Revoked));
    }

    #[test]
    fn destruction_is_allowed_from_every_state_except_destroyed() {
        let sources = [
            KeyStatus::Generated,
            KeyStatus::Active,
            KeyStatus::Rotating,
            KeyStatus::Retired,
            KeyStatus::Revoked,
        ];
        for &s in &sources {
            assert!(
                s.can_transition_to(KeyStatus::Destroyed),
                "{s} should be able to move to Destroyed"
            );
        }
        assert!(!KeyStatus::Destroyed.can_transition_to(KeyStatus::Destroyed));
    }

    #[test]
    fn destroyed_is_terminal() {
        let targets = [
            KeyStatus::Generated,
            KeyStatus::Active,
            KeyStatus::Rotating,
            KeyStatus::Retired,
            KeyStatus::Revoked,
        ];
        for &t in &targets {
            assert!(!KeyStatus::Destroyed.can_transition_to(t));
        }
    }

    #[test]
    fn revoked_is_not_resurrectable() {
        assert!(!KeyStatus::Revoked.can_transition_to(KeyStatus::Active));
        assert!(!KeyStatus::Revoked.can_transition_to(KeyStatus::Retired));
    }

    #[test]
    fn retired_cannot_become_active_again() {
        assert!(!KeyStatus::Retired.can_transition_to(KeyStatus::Active));
    }

    #[test]
    fn transition_to_returns_error_for_invalid_move() {
        let err = KeyStatus::Destroyed
            .transition_to(KeyStatus::Active)
            .unwrap_err();
        assert_eq!(err.from, KeyStatus::Destroyed);
        assert_eq!(err.to, KeyStatus::Active);
    }

    #[test]
    fn transition_to_returns_new_status_for_valid_move() {
        let next = KeyStatus::Generated
            .transition_to(KeyStatus::Active)
            .unwrap();
        assert_eq!(next, KeyStatus::Active);
    }

    #[test]
    fn usability_flags() {
        assert!(KeyStatus::Active.is_usable_for_new_work());
        assert!(!KeyStatus::Rotating.is_usable_for_new_work());
        assert!(!KeyStatus::Retired.is_usable_for_new_work());
        assert!(!KeyStatus::Revoked.is_usable_for_new_work());
        assert!(!KeyStatus::Destroyed.is_usable_for_new_work());

        assert!(KeyStatus::Retired.is_usable_for_verification());
        assert!(!KeyStatus::Destroyed.is_usable_for_verification());
    }

    #[test]
    fn material_presence_flags() {
        assert!(KeyStatus::Generated.is_material_present());
        assert!(KeyStatus::Revoked.is_material_present());
        assert!(!KeyStatus::Destroyed.is_material_present());
    }
}

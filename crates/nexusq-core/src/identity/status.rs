//! Identity lifecycle states.
//!
//! An identity moves through a small state machine during its life.
//! Unlike keys, identities do not have a "Generated" state: an identity
//! exists as soon as it is created, with a signing key already
//! activated. The states are therefore about trust, not existence.
//!
//! ```text
//! ACTIVE ──rotate──► ROTATING ──finalize──► ACTIVE
//!    │                                       
//!    └──revoke──► REVOKED (terminal)         
//! ```
//!
//! See ADR 0004 and `docs/KEY_MANAGEMENT.md` §5 for the key side of
//! this lifecycle.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Lifecycle state of an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityStatus {
    /// Normal operating state.
    ///
    /// The identity can sign, verify, and receive encrypted messages.
    Active,

    /// The identity is in the middle of a key rotation.
    ///
    /// Signatures made with the previous signing key still verify. New
    /// signatures use the replacement key. Verification tools must
    /// consult both.
    Rotating,

    /// The identity is no longer trusted.
    ///
    /// Revocation is terminal: an identity cannot come back. Past
    /// signatures remain verifiable if the corresponding public keys
    /// are still available, but new operations are refused.
    Revoked,
}

impl IdentityStatus {
    /// Returns the canonical lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
        }
    }

    /// Returns `true` if the identity can currently sign new messages.
    #[must_use]
    pub const fn can_sign(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns `true` if the identity is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }

    /// Returns `true` if the transition `self -> target` is allowed.
    #[must_use]
    pub const fn can_transition_to(self, target: IdentityStatus) -> bool {
        use IdentityStatus::{Active, Revoked, Rotating};
        matches!(
            (self, target),
            (Active, Rotating) | (Active, Revoked) | (Rotating, Active) | (Rotating, Revoked)
        )
    }

    /// Attempts to move to `target`.
    ///
    /// # Errors
    ///
    /// Returns [`StatusTransitionError`] if the transition is not
    /// allowed.
    pub fn transition_to(
        self,
        target: IdentityStatus,
    ) -> Result<IdentityStatus, StatusTransitionError> {
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

impl Serialize for IdentityStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for IdentityStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for IdentityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IdentityStatus {
    type Err = StatusParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "rotating" => Ok(Self::Rotating),
            "revoked" => Ok(Self::Revoked),
            other => Err(StatusParseError::Unknown(other.to_string())),
        }
    }
}

/// Error returned when a status transition is not allowed.
#[derive(Debug, thiserror::Error)]
#[error("invalid identity status transition: {from} -> {to}")]
pub struct StatusTransitionError {
    /// The state we were in.
    pub from: IdentityStatus,
    /// The state we tried to reach.
    pub to: IdentityStatus,
}

/// Errors returned when parsing an [`IdentityStatus`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StatusParseError {
    /// The input did not match any known status identifier.
    #[error("unknown identity status: {0}")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_strings_are_stable() {
        assert_eq!(IdentityStatus::Active.as_str(), "active");
        assert_eq!(IdentityStatus::Rotating.as_str(), "rotating");
        assert_eq!(IdentityStatus::Revoked.as_str(), "revoked");
    }

    #[test]
    fn roundtrip_display_and_parse() {
        for &s in &[
            IdentityStatus::Active,
            IdentityStatus::Rotating,
            IdentityStatus::Revoked,
        ] {
            let text = s.to_string();
            let parsed: IdentityStatus = text.parse().unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn parse_rejects_unknown() {
        assert!(matches!(
            "expired".parse::<IdentityStatus>(),
            Err(StatusParseError::Unknown(_))
        ));
    }

    #[test]
    fn only_active_can_sign() {
        assert!(IdentityStatus::Active.can_sign());
        assert!(!IdentityStatus::Rotating.can_sign());
        assert!(!IdentityStatus::Revoked.can_sign());
    }

    #[test]
    fn revoked_is_terminal() {
        assert!(IdentityStatus::Revoked.is_terminal());
        assert!(!IdentityStatus::Active.is_terminal());
        assert!(!IdentityStatus::Rotating.is_terminal());
    }

    #[test]
    fn active_can_rotate_or_revoke() {
        assert!(IdentityStatus::Active.can_transition_to(IdentityStatus::Rotating));
        assert!(IdentityStatus::Active.can_transition_to(IdentityStatus::Revoked));
    }

    #[test]
    fn rotating_can_finalize_or_revoke() {
        assert!(IdentityStatus::Rotating.can_transition_to(IdentityStatus::Active));
        assert!(IdentityStatus::Rotating.can_transition_to(IdentityStatus::Revoked));
    }

    #[test]
    fn revoked_has_no_outgoing_transitions() {
        assert!(!IdentityStatus::Revoked.can_transition_to(IdentityStatus::Active));
        assert!(!IdentityStatus::Revoked.can_transition_to(IdentityStatus::Rotating));
        assert!(!IdentityStatus::Revoked.can_transition_to(IdentityStatus::Revoked));
    }

    #[test]
    fn active_cannot_go_to_active() {
        assert!(!IdentityStatus::Active.can_transition_to(IdentityStatus::Active));
    }

    #[test]
    fn transition_to_returns_new_status_on_success() {
        assert_eq!(
            IdentityStatus::Active
                .transition_to(IdentityStatus::Rotating)
                .unwrap(),
            IdentityStatus::Rotating
        );
    }

    #[test]
    fn transition_to_returns_error_on_failure() {
        let err = IdentityStatus::Revoked
            .transition_to(IdentityStatus::Active)
            .unwrap_err();
        assert_eq!(err.from, IdentityStatus::Revoked);
        assert_eq!(err.to, IdentityStatus::Active);
    }
}

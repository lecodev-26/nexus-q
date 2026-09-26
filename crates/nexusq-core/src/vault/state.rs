//! Vault session state.
//!
//! A [`Session`](super::Session) exists in exactly one of four states.
//! The state gates what operations are allowed: a sealed session
//! refuses writes, a compromised session refuses everything.
//!
//! ## Lifecycle
//!
//! ```text
//! LOCKED ──unlock──► UNLOCKED ──lock──► LOCKED
//!                       │
//!                       ├──seal──► SEALED ──unseal──► UNLOCKED
//!                       │
//!                       └──tamper──► COMPROMISED (terminal)
//! ```
//!
//! ## What "compromised" means
//!
//! A session is compromised when a cryptographic operation fails in a
//! way that suggests the vault file was modified outside our control
//! (for example, a wrapped key no longer authenticates under the KEK
//! it was wrapped with). Once compromised, the session cannot perform
//! any operation; the caller must drop it and re-open the vault.
//!
//! ## Where the state lives
//!
//! The state is in-memory only. It is not persisted: a vault file has
//! no "compromised" flag. Re-opening the file starts a fresh LOCKED
//! vault; unlocking it starts a fresh UNLOCKED session.
//!
//! See `docs/SECURITY_MODEL.md` §4.1.

use std::fmt;

/// The state of a vault session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultState {
    /// The vault is closed. No KEK is loaded.
    ///
    /// A [`Vault`](super::Vault) that has not been unlocked is in this
    /// state. Sessions are never observed in it; unlocking consumes
    /// the transition.
    Locked,

    /// The vault is open and fully usable.
    Unlocked,

    /// The vault is open but refuses writes.
    ///
    /// Reading is allowed. Mutating operations are refused. This is
    /// useful for read-only workflows and for pausing before a
    /// maintenance operation.
    Sealed,

    /// The session is no longer trusted.
    ///
    /// All operations are refused. The session must be dropped.
    Compromised,
}

impl VaultState {
    /// Returns the canonical lowercase identifier of this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
            Self::Sealed => "sealed",
            Self::Compromised => "compromised",
        }
    }

    /// Returns `true` if reads are allowed in this state.
    #[must_use]
    pub const fn allows_reads(self) -> bool {
        matches!(self, Self::Unlocked | Self::Sealed)
    }

    /// Returns `true` if writes are allowed in this state.
    #[must_use]
    pub const fn allows_writes(self) -> bool {
        matches!(self, Self::Unlocked)
    }

    /// Returns `true` if the state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Compromised)
    }

    /// Returns `true` if the transition `self -> target` is allowed.
    #[must_use]
    pub const fn can_transition_to(self, target: VaultState) -> bool {
        use VaultState::{Compromised, Locked, Sealed, Unlocked};
        matches!(
            (self, target),
            (Locked, Unlocked)
                | (Unlocked, Locked)
                | (Unlocked, Sealed)
                | (Unlocked, Compromised)
                | (Sealed, Unlocked)
                | (Sealed, Compromised)
        )
    }

    /// Attempts to move to `target`.
    ///
    /// # Errors
    ///
    /// Returns [`StateTransitionError`] if the transition is not
    /// allowed.
    pub fn transition_to(self, target: VaultState) -> Result<VaultState, StateTransitionError> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(StateTransitionError {
                from: self,
                to: target,
            })
        }
    }
}

impl fmt::Display for VaultState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a vault state transition is not allowed.
#[derive(Debug, thiserror::Error)]
#[error("invalid vault state transition: {from} -> {to}")]
pub struct StateTransitionError {
    /// The state we were in.
    pub from: VaultState,
    /// The state we tried to reach.
    pub to: VaultState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_strings_are_stable() {
        assert_eq!(VaultState::Locked.as_str(), "locked");
        assert_eq!(VaultState::Unlocked.as_str(), "unlocked");
        assert_eq!(VaultState::Sealed.as_str(), "sealed");
        assert_eq!(VaultState::Compromised.as_str(), "compromised");
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(VaultState::Unlocked.to_string(), "unlocked");
    }

    #[test]
    fn unlocked_allows_reads_and_writes() {
        assert!(VaultState::Unlocked.allows_reads());
        assert!(VaultState::Unlocked.allows_writes());
    }

    #[test]
    fn sealed_allows_reads_but_not_writes() {
        assert!(VaultState::Sealed.allows_reads());
        assert!(!VaultState::Sealed.allows_writes());
    }

    #[test]
    fn locked_allows_neither() {
        assert!(!VaultState::Locked.allows_reads());
        assert!(!VaultState::Locked.allows_writes());
    }

    #[test]
    fn compromised_allows_neither() {
        assert!(!VaultState::Compromised.allows_reads());
        assert!(!VaultState::Compromised.allows_writes());
    }

    #[test]
    fn compromised_is_terminal() {
        assert!(VaultState::Compromised.is_terminal());
        assert!(!VaultState::Locked.is_terminal());
        assert!(!VaultState::Unlocked.is_terminal());
        assert!(!VaultState::Sealed.is_terminal());
    }

    #[test]
    fn normal_transitions_are_allowed() {
        assert!(VaultState::Locked.can_transition_to(VaultState::Unlocked));
        assert!(VaultState::Unlocked.can_transition_to(VaultState::Locked));
        assert!(VaultState::Unlocked.can_transition_to(VaultState::Sealed));
        assert!(VaultState::Sealed.can_transition_to(VaultState::Unlocked));
    }

    #[test]
    fn compromise_is_reachable_from_open_states() {
        assert!(VaultState::Unlocked.can_transition_to(VaultState::Compromised));
        assert!(VaultState::Sealed.can_transition_to(VaultState::Compromised));
        assert!(!VaultState::Locked.can_transition_to(VaultState::Compromised));
    }

    #[test]
    fn compromised_has_no_outgoing_transitions() {
        assert!(!VaultState::Compromised.can_transition_to(VaultState::Locked));
        assert!(!VaultState::Compromised.can_transition_to(VaultState::Unlocked));
        assert!(!VaultState::Compromised.can_transition_to(VaultState::Sealed));
        assert!(!VaultState::Compromised.can_transition_to(VaultState::Compromised));
    }

    #[test]
    fn sealed_cannot_go_directly_to_locked() {
        assert!(!VaultState::Sealed.can_transition_to(VaultState::Locked));
    }

    #[test]
    fn transition_to_returns_new_state_on_success() {
        assert_eq!(
            VaultState::Unlocked
                .transition_to(VaultState::Sealed)
                .unwrap(),
            VaultState::Sealed
        );
    }

    #[test]
    fn transition_to_returns_error_on_failure() {
        let err = VaultState::Compromised
            .transition_to(VaultState::Unlocked)
            .unwrap_err();
        assert_eq!(err.from, VaultState::Compromised);
        assert_eq!(err.to, VaultState::Unlocked);
    }
}

//! Timestamps.
//!
//! NEXUS-Q records when things happen. A [`Timestamp`] is a count of
//! seconds since the UNIX epoch (1970-01-01T00:00:00Z), stored as an
//! unsigned 64-bit integer.
//!
//! ## Why not a rich date type
//!
//! The alternative is a type like `chrono::DateTime<Utc>`, which is
//! ergonomic but adds a dependency and surface area. Timestamps in
//! NEXUS-Q are written to disk and compared; they are never displayed
//! by the core library. Presentation is the caller's problem, and a
//! `u64` is the universal representation any frontend can consume.
//!
//! ## What this type is NOT
//!
//! NEXUS-Q never relies on the system clock for security decisions
//! alone. See `docs/THREAT_MODEL.md` §5.5. A timestamp is data, not a
//! trusted authority. Expiration checks and rotation deadlines must be
//! combined with other signals (policy, hardware counters, explicit
//! user action) before they affect a security-sensitive operation.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A count of seconds since the UNIX epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Creates a timestamp from a raw seconds value.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// Returns the underlying seconds value.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Returns the current time, if the system clock is available and
    /// set to a value at or after the UNIX epoch.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::ClockBeforeEpoch`] if the system clock
    /// reports a time before 1970-01-01, which usually indicates a
    /// misconfigured device.
    pub fn now() -> Result<Self, TimestampError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TimestampError::ClockBeforeEpoch)?;
        Ok(Self(now.as_secs()))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Errors returned by timestamp operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TimestampError {
    /// The system clock reports a time before the UNIX epoch.
    #[error("system clock is before the UNIX epoch")]
    ClockBeforeEpoch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_secs_and_as_secs_roundtrip() {
        let t = Timestamp::from_secs(1_700_000_000);
        assert_eq!(t.as_secs(), 1_700_000_000);
    }

    #[test]
    fn now_is_after_a_known_past_instant() {
        // 2020-01-01T00:00:00Z = 1577836800
        let t = Timestamp::now().unwrap();
        assert!(t.as_secs() > 1_577_836_800);
    }

    #[test]
    fn ordering_is_numeric() {
        let a = Timestamp::from_secs(100);
        let b = Timestamp::from_secs(200);
        assert!(a < b);
    }

    #[test]
    fn display_shows_seconds() {
        let t = Timestamp::from_secs(42);
        assert_eq!(t.to_string(), "42");
    }
}

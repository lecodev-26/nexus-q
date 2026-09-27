//! Backend trait.
//!
//! A [`Backend`] bundles one implementation of each hardware trait.
//! Code that needs hardware facilities depends on `dyn Backend` and
//! receives the right implementation at construction time, rather than
//! picking between software and hardware at every call site.
//!
//! The traits themselves remain available individually, for cases
//! where a caller needs only one capability.
//!
//! See `docs/ARCHITECTURE.md` §6.

use super::{AttestationProvider, KeyProvider, RandomSource, SecureMemory, SecureStorage};

/// One implementation of every hardware capability.
pub trait Backend: Send + Sync {
    /// Cryptographic randomness.
    fn random(&self) -> &dyn RandomSource;

    /// Persistent, tamper-resistant storage.
    fn storage(&self) -> &dyn SecureStorage;

    /// Keys that live outside the vault's own memory.
    fn keys(&self) -> &dyn KeyProvider;

    /// Ability to prove which software is running.
    fn attestation(&self) -> &dyn AttestationProvider;

    /// Memory that resists swapping and inspection.
    fn secure_memory(&self) -> &dyn SecureMemory;

    /// Human-readable name, for diagnostics and audit records.
    fn name(&self) -> &'static str;
}

//! Exit codes for the `nexusq` binary.
//!
//! The codes follow `docs/API.md` §6.3 so that scripts can branch on
//! failures without parsing stderr. The mapping from
//! [`nexusq_core::Error`] to a code lives in [`crate::error`].

/// Success.
pub const SUCCESS: i32 = 0;

/// Generic error not covered by a more specific code.
pub const GENERIC: i32 = 1;

/// Usage error: bad arguments, unknown command.
pub const USAGE: i32 = 2;

/// Authentication failure: wrong password, locked vault.
pub const AUTHENTICATION: i32 = 3;

/// Authorization failure: refused by policy.
pub const AUTHORIZATION: i32 = 4;

/// Integrity failure: tamper detected, corrupt file.
pub const INTEGRITY: i32 = 5;

/// Hardware failure: TPM, HSM or Secure Element problem.
pub const HARDWARE: i32 = 6;

/// I/O failure: file not found, permission denied.
pub const IO: i32 = 7;

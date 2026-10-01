//! CLI errors and their mapping to exit codes.
//!
//! Everything the CLI can fail with funnels through [`CliError`]. The
//! variant chosen determines the process exit code, so scripts can
//! branch on `$?` without parsing stderr.
//!
//! See `crate::exit_codes` for the code constants and `docs/API.md`
//! §6.3 for their meaning.

use nexusq_core::vault::VaultError;

use crate::exit_codes;

/// The error type returned by every subcommand.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Bad usage: unknown argument, malformed value.
    #[error("{0}")]
    Usage(String),

    /// Authentication failure: wrong password, locked vault.
    #[error("{0}")]
    Authentication(String),

    /// Authorization failure: refused by policy.
    #[error("{0}")]
    Authorization(String),

    /// Integrity failure: tamper detected, corrupt file.
    #[error("{0}")]
    Integrity(String),

    /// Hardware failure: TPM, HSM or Secure Element problem.
    #[error("{0}")]
    Hardware(String),

    /// I/O failure: file not found, permission denied.
    #[error("{0}")]
    Io(String),

    /// Anything else.
    #[error("{0}")]
    Generic(String),
}

impl CliError {
    /// Returns the process exit code for this error.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => exit_codes::USAGE,
            Self::Authentication(_) => exit_codes::AUTHENTICATION,
            Self::Authorization(_) => exit_codes::AUTHORIZATION,
            Self::Integrity(_) => exit_codes::INTEGRITY,
            Self::Hardware(_) => exit_codes::HARDWARE,
            Self::Io(_) => exit_codes::IO,
            Self::Generic(_) => exit_codes::GENERIC,
        }
    }
}

/// Maps a vault error to a CLI error.
///
/// The mapping is coarse on purpose: a script branches on categories,
/// not on every internal cause.
impl From<VaultError> for CliError {
    fn from(err: VaultError) -> Self {
        match err {
            VaultError::WrongPassword => Self::Authentication(err.to_string()),
            VaultError::Io(_) => Self::Io(err.to_string()),
            VaultError::Audit(_) => Self::Integrity(err.to_string()),
            VaultError::PolicyDenied(_) | VaultError::StateDenied { .. } => {
                Self::Authorization(err.to_string())
            }
            VaultError::IdentityNotUsable { .. } => Self::Authorization(err.to_string()),
            VaultError::Corrupt(_)
            | VaultError::BadMagic
            | VaultError::UnsupportedVersion(_)
            | VaultError::Cbor(_)
            | VaultError::Aead(_)
            | VaultError::RecordValidation(_)
            | VaultError::Wrapping(_)
            | VaultError::Header(_) => Self::Integrity(err.to_string()),
            _ => Self::Generic(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexusq_core::policy::PolicyDecision;

    #[test]
    fn cli_error_maps_to_expected_codes() {
        assert_eq!(CliError::Usage("x".into()).exit_code(), exit_codes::USAGE);
        assert_eq!(
            CliError::Authentication("x".into()).exit_code(),
            exit_codes::AUTHENTICATION
        );
        assert_eq!(
            CliError::Authorization("x".into()).exit_code(),
            exit_codes::AUTHORIZATION
        );
        assert_eq!(
            CliError::Integrity("x".into()).exit_code(),
            exit_codes::INTEGRITY
        );
        assert_eq!(
            CliError::Hardware("x".into()).exit_code(),
            exit_codes::HARDWARE
        );
        assert_eq!(CliError::Io("x".into()).exit_code(), exit_codes::IO);
        assert_eq!(
            CliError::Generic("x".into()).exit_code(),
            exit_codes::GENERIC
        );
    }

    #[test]
    fn wrong_password_maps_to_authentication() {
        let err: CliError = VaultError::WrongPassword.into();
        assert_eq!(err.exit_code(), exit_codes::AUTHENTICATION);
    }

    #[test]
    fn policy_denied_maps_to_authorization() {
        let err: CliError = VaultError::PolicyDenied(PolicyDecision::NoDecision).into();
        assert_eq!(err.exit_code(), exit_codes::AUTHORIZATION);
    }

    #[test]
    fn corrupt_vault_maps_to_integrity() {
        let err: CliError = VaultError::BadMagic.into();
        assert_eq!(err.exit_code(), exit_codes::INTEGRITY);
    }
}

//! Digital identities and signing.
//!
//! Each submodule exposes its own error type. [`IdentityError`]
//! unifies them so callers that do not care about the distinction
//! can use one type.

pub mod credential;
pub mod id;
pub mod record;
pub mod status;

pub use credential::{CURRENT_VERSION as CREDENTIAL_VERSION, Credential, CredentialError};
pub use id::{IdentityId, IdentityIdError};
pub use record::{Identity, IdentityMetadata, IdentityValidationError};
pub use status::{IdentityStatus, StatusParseError, StatusTransitionError};

/// Error type for identity operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// Identifier parsing or generation failed.
    #[error("identity id error: {0}")]
    Id(#[from] IdentityIdError),

    /// Status parsing failed.
    #[error("identity status error: {0}")]
    Status(#[from] StatusParseError),

    /// Status transition failed.
    #[error("identity status transition error: {0}")]
    Transition(#[from] StatusTransitionError),

    /// Identity validation failed.
    #[error("identity validation error: {0}")]
    Validation(#[from] IdentityValidationError),

    /// Credential operation failed.
    #[error("credential error: {0}")]
    Credential(#[from] CredentialError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_identity_id_error() {
        let err: IdentityError = IdentityIdError::MissingPrefix.into();
        assert!(matches!(err, IdentityError::Id(_)));
    }

    #[test]
    fn from_status_parse_error() {
        let err: IdentityError = StatusParseError::Unknown("x".into()).into();
        assert!(matches!(err, IdentityError::Status(_)));
    }

    #[test]
    fn from_validation_error() {
        let err: IdentityError = IdentityValidationError::VersionZero.into();
        assert!(matches!(err, IdentityError::Validation(_)));
    }

    #[test]
    fn from_credential_error() {
        let err: IdentityError = CredentialError::UnsupportedVersion(99).into();
        assert!(matches!(err, IdentityError::Credential(_)));
    }
}

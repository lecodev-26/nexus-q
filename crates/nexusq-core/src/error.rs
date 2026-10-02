//! Unified error type.
//!
//! Every module in the crate exposes a specific error type. This
//! module defines [`Error`], a single enum that wraps the top-level
//! error of each module so a caller that does not care about the
//! distinction can use one type, and a [`Result`] alias that uses it.
//!
//! The variants are coarse on purpose: they tell the caller which
//! subsystem failed, not every possible cause inside it. Callers that
//! need the specific cause match on the inner error.

pub use crate::crypto::CryptoError;
pub use crate::hardware::HardwareError;
pub use crate::identity::IdentityError;
pub use crate::policy::PolicyError;
pub use crate::storage::StorageError;
pub use crate::vault::VaultError;

/// Result type alias for the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type for the crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Cryptographic primitive failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Vault operation failed.
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),

    /// Identity operation failed.
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    /// Policy evaluation failed.
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),

    /// Storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// Hardware backend failed.
    #[error("hardware error: {0}")]
    Hardware(#[from] HardwareError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_vault_error() {
        let inner: VaultError = VaultError::WrongPassword;
        let err: Error = inner.into();
        assert!(matches!(err, Error::Vault(_)));
    }

    #[test]
    fn from_crypto_error() {
        let inner: CryptoError = CryptoError::Aead(crate::crypto::AeadError::InvalidKey);
        let err: Error = inner.into();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn from_policy_error() {
        let inner: PolicyError = PolicyError::Serialization;
        let err: Error = inner.into();
        assert!(matches!(err, Error::Policy(_)));
    }

    #[test]
    fn from_storage_error() {
        let inner: StorageError = StorageError::Db(crate::storage::DbError::BadMagic);
        let err: Error = inner.into();
        assert!(matches!(err, Error::Storage(_)));
    }

    #[test]
    fn from_hardware_error() {
        let inner: HardwareError = HardwareError::NotAvailable;
        let err: Error = inner.into();
        assert!(matches!(err, Error::Hardware(_)));
    }

    #[test]
    fn from_identity_error() {
        let inner: IdentityError =
            IdentityError::Id(crate::identity::IdentityIdError::MissingPrefix);
        let err: Error = inner.into();
        assert!(matches!(err, Error::Identity(_)));
    }

    #[test]
    fn display_prefixes_the_subsystem() {
        let err: Error = VaultError::WrongPassword.into();
        assert!(err.to_string().starts_with("vault error:"));
    }
}

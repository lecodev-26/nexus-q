//! PKCS#11-backed ML-DSA-65 signing and quorum-authorized key ceremonies.

mod ceremony;
mod provider;

pub use ceremony::{
    CeremonyAction, CeremonyCoordinator, CeremonyError, CeremonyParticipant, CeremonyRequest,
    CeremonyStatus,
};
pub use provider::{HsmKeyStore, Pkcs11KeyRef, Pkcs11MlDsaSigner, Pkcs11Provider};

/// Errors from PKCS#11 operations and key ceremonies. PINs and private key material are never included.
#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    #[error("PKCS#11 operation failed: {0}")]
    Pkcs11(String),
    #[error("invalid PKCS#11 configuration or token reference")]
    InvalidConfig,
    #[error("invalid HSM object label")]
    InvalidLabel,
    #[error("key reference not found")]
    KeyNotFound,
    #[error("an object with this label already exists")]
    KeyAlreadyExists,
    #[error("multiple PKCS#11 objects match the same key reference")]
    KeyReferenceAmbiguous,
    #[error("HSM returned an invalid ML-DSA-65 public key")]
    InvalidPublicKey,
    #[error("message exceeds the configured signing limit")]
    MessageTooLarge,
    #[error("secure random generation failed")]
    Randomness,
}

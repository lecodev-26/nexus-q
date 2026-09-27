//! Digital identities and signing.

pub mod credential;
pub mod id;
pub mod record;
pub mod status;

pub use credential::{CURRENT_VERSION as CREDENTIAL_VERSION, Credential, CredentialError};
pub use id::{IdentityId, IdentityIdError};
pub use record::{Identity, IdentityMetadata, IdentityValidationError};
pub use status::{IdentityStatus, StatusParseError, StatusTransitionError};

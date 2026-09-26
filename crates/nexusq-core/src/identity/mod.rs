//! Digital identities and signing.

pub mod id;
pub mod record;
pub mod status;

pub use id::{IdentityId, IdentityIdError};
pub use record::{Identity, IdentityMetadata, IdentityValidationError};
pub use status::{IdentityStatus, StatusParseError, StatusTransitionError};

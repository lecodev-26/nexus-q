//! Key storage and lifecycle management.

pub mod algorithm;
pub mod body;
pub mod key_id;
pub mod metadata;
pub mod purpose;
pub mod record;
pub mod serde_helpers;
pub mod status;
pub mod timestamp;

pub use algorithm::{Algorithm, AlgorithmError, Category};
pub use body::{CURRENT_SCHEMA_VERSION, VaultBody, VaultMetadata};
pub use key_id::{KeyId, KeyIdError};
pub use metadata::{KeyMetadata, Origin};
pub use purpose::{Purpose, PurposeError};
pub use record::{KeyRecord, RecordValidationError, WrappedKeyMaterial};
pub use serde_helpers::{CborError, from_slice, to_vec};
pub use status::{KeyStatus, StatusParseError, StatusTransitionError};
pub use timestamp::{Timestamp, TimestampError};

//! Key storage and lifecycle management.

pub mod algorithm;
pub mod body;
pub mod container;
pub mod envelope;
pub mod file_ops;
pub mod header;
pub mod key_id;
pub mod lifecycle;
pub mod metadata;
pub mod purpose;
pub mod record;
pub mod serde_helpers;
pub mod state;
pub mod status;
pub mod timestamp;
pub mod wrapping;

pub use algorithm::{Algorithm, AlgorithmError, Category};
pub use body::{CURRENT_SCHEMA_VERSION, VaultBody, VaultMetadata};
pub use container::{Session, Vault, VaultError};
pub use envelope::{
    Envelope, EnvelopeAlgorithm, EnvelopeHeader, FORMAT_VERSION as ENVELOPE_FORMAT_VERSION,
    MAGIC as ENVELOPE_MAGIC,
};
pub use file_ops::{
    ENCRYPTED_EXTENSION, decrypt_file_with_kem, decrypt_file_with_key, encrypt_file_to_public_key,
    encrypt_file_with_key, encrypted_path_for,
};
pub use header::{
    FORMAT_VERSION, HeaderError, KdfAlgorithm, KdfParams, MAGIC, SALT_LEN, VaultHeader,
};
pub use key_id::{KeyId, KeyIdError};
pub use lifecycle::{DestructionConfirmation, LifecycleError, RevokeReason};
pub use metadata::{KeyMetadata, Origin};
pub use purpose::{Purpose, PurposeError};
pub use record::{KeyRecord, RecordValidationError, WrappedKeyMaterial};
pub use serde_helpers::{CborError, from_slice, to_vec};
pub use state::{StateTransitionError, VaultState};
pub use status::{KeyStatus, StatusParseError, StatusTransitionError};
pub use timestamp::{Timestamp, TimestampError};
pub use wrapping::{WrappingError, unwrap, wrap};

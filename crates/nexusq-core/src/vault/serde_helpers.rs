//! CBOR roundtrip helpers and tests.
//!
//! The vault body is serialized with CBOR (see `docs/adr/0002`). This
//! module provides two small wrappers around `ciborium` that we use
//! everywhere, so that error handling stays consistent and so that
//! serialization failures are visible in one place.
//!
//! It also contains roundtrip tests for every vault type. If a type
//! loses its `Serialize` or `Deserialize` implementation, these tests
//! fail before anything reaches the storage layer.

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Errors returned by the CBOR helpers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CborError {
    /// Serialization failed.
    #[error("failed to serialize value")]
    Serialize,

    /// Deserialization failed.
    #[error("failed to deserialize value")]
    Deserialize,
}

/// Serializes `value` to CBOR bytes.
///
/// # Errors
///
/// Returns [`CborError::Serialize`] if the value cannot be encoded.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|_| CborError::Serialize)?;
    Ok(out)
}

/// Deserializes a value from CBOR bytes.
///
/// # Errors
///
/// Returns [`CborError::Deserialize`] if the input is not valid CBOR
/// or does not match the expected type.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CborError> {
    ciborium::from_reader(bytes).map_err(|_| CborError::Deserialize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;
    use crate::vault::{Algorithm, KeyId, KeyMetadata, KeyStatus, Origin, Purpose, Timestamp};

    fn roundtrip<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let bytes = to_vec(value).expect("serialize");
        let back: T = from_slice(&bytes).expect("deserialize");
        assert_eq!(*value, back);
    }

    #[test]
    fn algorithm_roundtrip() {
        for &alg in Algorithm::all() {
            roundtrip(&alg);
        }
    }

    #[test]
    fn purpose_roundtrip() {
        for &p in Purpose::all() {
            roundtrip(&p);
        }
    }

    #[test]
    fn key_status_roundtrip() {
        for &s in &[
            KeyStatus::Generated,
            KeyStatus::Active,
            KeyStatus::Rotating,
            KeyStatus::Retired,
            KeyStatus::Revoked,
            KeyStatus::Destroyed,
        ] {
            roundtrip(&s);
        }
    }

    #[test]
    fn origin_roundtrip() {
        roundtrip(&Origin::Generated);
        roundtrip(&Origin::Imported);
        roundtrip(&Origin::Derived);
    }

    #[test]
    fn timestamp_roundtrip() {
        roundtrip(&Timestamp::from_secs(1_700_000_000));
    }

    #[test]
    fn key_id_roundtrip() {
        let src = OsRandomSource::new();
        let id = KeyId::generate(&src, "ed25519").unwrap();
        roundtrip(&id);
    }

    #[test]
    fn key_metadata_roundtrip() {
        let src = OsRandomSource::new();
        let key_id = KeyId::generate(&src, "ed25519").unwrap();
        let md = KeyMetadata {
            key_id,
            algorithm: Algorithm::Ed25519,
            purpose: Purpose::Sign,
            created_at: Timestamp::from_secs(1_700_000_000),
            created_by: "test".to_string(),
            created_from: Origin::Generated,
            status: KeyStatus::Active,
            version: 1,
            owner: Some("alice".to_string()),
            rotation_due: Some(Timestamp::from_secs(1_800_000_000)),
            expires_at: Some(Timestamp::from_secs(1_900_000_000)),
            parent_key_id: None,
            hardware_backed: false,
            attestation: None,
        };
        roundtrip(&md);
    }

    #[test]
    fn from_slice_rejects_garbage() {
        let garbage = [0xff, 0xfe, 0xfd, 0xfc];
        let res: Result<Algorithm, _> = from_slice(&garbage);
        assert!(res.is_err());
    }
}

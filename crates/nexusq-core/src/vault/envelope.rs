//! Envelope encryption (format F-02).
//!
//! An envelope protects user data: files, messages, records. It carries
//! everything needed to decrypt except the key, which is either a key
//! in the local vault (vault mode) or a recipient's public key
//! (public-key mode, implemented later in this phase).
//!
//! ## Layout
//!
//! See ADR 0003. The whole envelope is a single CBOR document:
//!
//! ```text
//! Envelope {
//!     header:       EnvelopeHeader,
//!     wrapped_dek:  bytes,
//!     ciphertext:   bytes,
//! }
//! ```
//!
//! The header carries the algorithm, the KeyId, a nonce and optional
//! application metadata. It is authenticated twice: once as AAD when
//! wrapping the DEK (through the KeyId) and once as AAD when
//! encrypting the payload.
//!
//! ## Threat model
//!
//! - Tampering with any header field: detected by the payload's AEAD
//!   tag, because the header is part of its AAD.
//! - Tampering with the wrapped DEK: detected when the DEK is
//!   unwrapped.
//! - Tampering with the ciphertext: detected by the AEAD tag.
//! - Using the wrong vault key: rejected because the AAD includes the
//!   KeyId.
//!
//! See `docs/STORAGE.md` §5 and ADR 0003.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use zeroize::Zeroizing;

use crate::crypto::aead::{self, AeadError, Algorithm as AeadAlgorithm};
use crate::crypto::kdf::DERIVED_KEY_LEN;
use crate::crypto::random::{OsRandomSource, RandomError, RandomSource};

use super::key_id::KeyId;
use super::record::KeyRecord;
use super::serde_helpers::{self, CborError};
use super::status::KeyStatus;
use super::wrapping::{self, WrappingError};

/// File magic for the envelope format.
pub const MAGIC: [u8; 4] = *b"NQX1";

/// Current envelope format version.
pub const FORMAT_VERSION: u8 = 1;

/// Length in bytes of the payload AEAD nonce.
pub const NONCE_LEN: usize = crate::crypto::aead::NONCE_LEN;

/// Identifier of the AEAD algorithm used for the payload.
///
/// We wrap the crypto crate's enum to control its serialization: the
/// crypto crate is free to change its own layout, this one is ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeAlgorithm {
    /// AES-256-GCM, the default.
    #[serde(rename = "aes256gcm")]
    Aes256Gcm,
    /// ChaCha20-Poly1305, for platforms without AES acceleration.
    #[serde(rename = "chacha20poly1305")]
    ChaCha20Poly1305,
}

impl EnvelopeAlgorithm {
    /// Returns the canonical lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes256gcm",
            Self::ChaCha20Poly1305 => "chacha20poly1305",
        }
    }

    /// Converts to the crypto crate's algorithm enum.
    #[must_use]
    pub const fn to_crypto(self) -> AeadAlgorithm {
        match self {
            Self::Aes256Gcm => AeadAlgorithm::Aes256Gcm,
            Self::ChaCha20Poly1305 => AeadAlgorithm::ChaCha20Poly1305,
        }
    }
}

/// Errors returned by envelope operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// CBOR (de)serialization failed.
    #[error("cbor error: {0}")]
    Cbor(#[from] CborError),

    /// AEAD encryption or decryption of the payload failed.
    #[error("aead error: {0}")]
    Aead(#[from] AeadError),

    /// Wrapping or unwrapping the DEK failed.
    #[error("wrapping error: {0}")]
    Wrapping(#[from] WrappingError),

    /// Randomness generation failed.
    #[error("random error: {0}")]
    Random(#[from] RandomError),

    /// The envelope's magic, version or flags are not supported.
    #[error("unsupported envelope format")]
    UnsupportedFormat,

    /// The key needed to open the envelope is not in the vault.
    #[error("key not found in vault: {0}")]
    KeyNotFound(KeyId),

    /// The key exists but is not in a state that allows the operation.
    #[error("key {key_id} is {status}; cannot be used for this operation")]
    KeyNotUsable {
        /// The key in question.
        key_id: KeyId,
        /// Its current status.
        status: KeyStatus,
    },

    /// The key is not of a category that can encrypt or decrypt data.
    #[error("key {key_id} uses algorithm {algorithm}, which is not a symmetric cipher")]
    WrongCategory {
        /// The key in question.
        key_id: KeyId,
        /// Its algorithm.
        algorithm: crate::vault::Algorithm,
    },
}

/// The header of an envelope.
///
/// The header is authenticated by the payload's AEAD tag; it is not
/// encrypted. It may contain application metadata (a filename, a
/// timestamp, a size) that the receiver can inspect before decrypting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    /// File magic: always [`MAGIC`].
    pub magic: [u8; 4],

    /// Format version: always [`FORMAT_VERSION`] for v1.
    pub version: u8,

    /// Reserved flags. Must be zero in v1.
    pub flags: u16,

    /// AEAD algorithm for the payload.
    pub algorithm: EnvelopeAlgorithm,

    /// The vault key that protects the DEK.
    pub key_id: KeyId,

    /// Nonce for the payload AEAD.
    pub nonce: [u8; NONCE_LEN],

    /// Application metadata. Authenticated, not encrypted. May be empty.
    #[serde(with = "serde_bytes")]
    pub metadata: Vec<u8>,
}

impl EnvelopeHeader {
    /// Returns `true` if the header's magic, version and flags are
    /// consistent with this build.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.magic == MAGIC && self.version == FORMAT_VERSION && self.flags == 0
    }
}

/// A full envelope: header plus wrapped DEK plus payload ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// The header.
    pub header: EnvelopeHeader,

    /// The DEK, wrapped under the key identified by `header.key_id`.
    pub wrapped_dek: ByteBuf,

    /// The payload, AEAD-encrypted with the DEK.
    pub ciphertext: ByteBuf,
}

// =============================================================================
// Envelope construction and opening
// =============================================================================

/// Length in bytes of the DEK.
const DEK_LEN: usize = DERIVED_KEY_LEN;

/// Builds an envelope that protects `plaintext` under the vault key
/// described by `key_record`, using `kek` to wrap the freshly generated
/// DEK.
///
/// Returns the CBOR encoding of the whole envelope.
///
/// # Errors
///
/// Returns [`EnvelopeError::WrongCategory`] if the key is not an AEAD
/// algorithm, [`EnvelopeError::KeyNotUsable`] if it is not `Active`,
/// or another error if generation, wrapping or encryption fails.
pub fn build_envelope(
    kek: &[u8],
    key_record: &KeyRecord,
    plaintext: &[u8],
    metadata: Vec<u8>,
) -> Result<Vec<u8>, EnvelopeError> {
    let key_id = key_record.key_id().clone();
    let algorithm = key_record.algorithm();

    // Only AEAD algorithms can protect data.
    if algorithm.category() != crate::vault::Category::Aead {
        return Err(EnvelopeError::WrongCategory { key_id, algorithm });
    }
    if key_record.status() != KeyStatus::Active {
        return Err(EnvelopeError::KeyNotUsable {
            key_id,
            status: key_record.status(),
        });
    }

    let mut rng = OsRandomSource::new();

    // Fresh DEK and payload nonce.
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    rng.fill_bytes(dek.as_mut())?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce)?;

    // Envelope algorithm mirrors the key's algorithm.
    let env_alg = envelope_algorithm_from(algorithm).ok_or(EnvelopeError::WrongCategory {
        key_id: key_id.clone(),
        algorithm,
    })?;

    let header = EnvelopeHeader {
        magic: MAGIC,
        version: FORMAT_VERSION,
        flags: 0,
        algorithm: env_alg,
        key_id: key_id.clone(),
        nonce,
        metadata,
    };

    // AAD for the payload is the CBOR encoding of the header.
    let header_bytes = serde_helpers::to_vec(&header)?;

    let ciphertext = aead::encrypt(
        env_alg.to_crypto(),
        dek.as_ref(),
        &nonce,
        &header_bytes,
        plaintext,
    )?;

    // Wrap the DEK under the vault KEK, bound to the KeyId.
    let wrapped_dek = wrapping::wrap(dek.as_ref(), kek, &key_id)?;

    let envelope = Envelope {
        header,
        wrapped_dek: ByteBuf::from(wrapped_dek),
        ciphertext: ByteBuf::from(ciphertext),
    };

    Ok(serde_helpers::to_vec(&envelope)?)
}

/// Opens an envelope, returning the plaintext.
///
/// `kek` is the vault's KEK. `key_lookup` resolves the envelope's
/// KeyId to a [`KeyRecord`]; it is called once with the KeyId found in
/// the envelope.
///
/// # Errors
///
/// Returns [`EnvelopeError::UnsupportedFormat`] if the magic, version
/// or flags are not recognized, [`EnvelopeError::KeyNotFound`] if the
/// lookup returns `None`, [`EnvelopeError::KeyNotUsable`] if the key
/// is in a state that cannot decrypt, or another error if unwrapping
/// or decryption fails.
pub fn open_envelope<F>(
    kek: &[u8],
    envelope_bytes: &[u8],
    key_lookup: F,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError>
where
    F: FnOnce(&KeyId) -> Option<KeyRecord>,
{
    let envelope: Envelope = serde_helpers::from_slice(envelope_bytes)?;

    if !envelope.header.is_supported() {
        return Err(EnvelopeError::UnsupportedFormat);
    }

    let key_id = &envelope.header.key_id;
    let key_record =
        key_lookup(key_id).ok_or_else(|| EnvelopeError::KeyNotFound(key_id.clone()))?;

    // Decryption is allowed from every state except Generated and
    // Destroyed. Rotating, Retired and Revoked can still recover data
    // that was protected while the key was active.
    match key_record.status() {
        KeyStatus::Active | KeyStatus::Rotating | KeyStatus::Retired | KeyStatus::Revoked => {}
        status => {
            return Err(EnvelopeError::KeyNotUsable {
                key_id: key_id.clone(),
                status,
            });
        }
    }

    // Unwrap the DEK.
    let dek = wrapping::unwrap(&envelope.wrapped_dek, kek, key_id)?;

    // AAD for the payload is the CBOR encoding of the header as parsed.
    let header_bytes = serde_helpers::to_vec(&envelope.header)?;

    let plaintext = aead::decrypt(
        envelope.header.algorithm.to_crypto(),
        dek.as_ref(),
        &envelope.header.nonce,
        &header_bytes,
        &envelope.ciphertext,
    )?;

    Ok(Zeroizing::new(plaintext))
}

fn envelope_algorithm_from(algorithm: crate::vault::Algorithm) -> Option<EnvelopeAlgorithm> {
    use crate::vault::Algorithm;
    match algorithm {
        Algorithm::Aes256Gcm => Some(EnvelopeAlgorithm::Aes256Gcm),
        Algorithm::ChaCha20Poly1305 => Some(EnvelopeAlgorithm::ChaCha20Poly1305),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;

    fn sample_key_id() -> KeyId {
        let mut rng = OsRandomSource::new();
        KeyId::generate(&mut rng, "aes256gcm").unwrap()
    }

    #[test]
    fn algorithm_strings_are_stable() {
        assert_eq!(EnvelopeAlgorithm::Aes256Gcm.as_str(), "aes256gcm");
        assert_eq!(
            EnvelopeAlgorithm::ChaCha20Poly1305.as_str(),
            "chacha20poly1305"
        );
    }

    #[test]
    fn algorithm_to_crypto_maps_correctly() {
        assert_eq!(
            EnvelopeAlgorithm::Aes256Gcm.to_crypto(),
            AeadAlgorithm::Aes256Gcm
        );
        assert_eq!(
            EnvelopeAlgorithm::ChaCha20Poly1305.to_crypto(),
            AeadAlgorithm::ChaCha20Poly1305
        );
    }

    #[test]
    fn header_is_supported_when_fresh() {
        let header = EnvelopeHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            algorithm: EnvelopeAlgorithm::Aes256Gcm,
            key_id: sample_key_id(),
            nonce: [0u8; NONCE_LEN],
            metadata: Vec::new(),
        };
        assert!(header.is_supported());
    }

    #[test]
    fn header_rejects_wrong_magic() {
        let mut header = EnvelopeHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            algorithm: EnvelopeAlgorithm::Aes256Gcm,
            key_id: sample_key_id(),
            nonce: [0u8; NONCE_LEN],
            metadata: Vec::new(),
        };
        header.magic = *b"XXXX";
        assert!(!header.is_supported());
    }

    #[test]
    fn header_rejects_unknown_version() {
        let mut header = EnvelopeHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            algorithm: EnvelopeAlgorithm::Aes256Gcm,
            key_id: sample_key_id(),
            nonce: [0u8; NONCE_LEN],
            metadata: Vec::new(),
        };
        header.version = 99;
        assert!(!header.is_supported());
    }

    #[test]
    fn header_rejects_nonzero_flags() {
        let mut header = EnvelopeHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            algorithm: EnvelopeAlgorithm::Aes256Gcm,
            key_id: sample_key_id(),
            nonce: [0u8; NONCE_LEN],
            metadata: Vec::new(),
        };
        header.flags = 1;
        assert!(!header.is_supported());
    }

    #[test]
    fn header_roundtrips_through_cbor() {
        let header = EnvelopeHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            algorithm: EnvelopeAlgorithm::Aes256Gcm,
            key_id: sample_key_id(),
            nonce: [0x42; NONCE_LEN],
            metadata: b"filename.txt".to_vec(),
        };
        let bytes = crate::vault::serde_helpers::to_vec(&header).unwrap();
        let back: EnvelopeHeader = crate::vault::serde_helpers::from_slice(&bytes).unwrap();
        assert_eq!(back, header);
    }

    #[test]
    fn envelope_roundtrips_through_cbor() {
        let envelope = Envelope {
            header: EnvelopeHeader {
                magic: MAGIC,
                version: FORMAT_VERSION,
                flags: 0,
                algorithm: EnvelopeAlgorithm::Aes256Gcm,
                key_id: sample_key_id(),
                nonce: [0x24; NONCE_LEN],
                metadata: Vec::new(),
            },
            wrapped_dek: ByteBuf::from(vec![0u8; 60]),
            ciphertext: ByteBuf::from(vec![1u8; 128]),
        };
        let bytes = crate::vault::serde_helpers::to_vec(&envelope).unwrap();
        let back: Envelope = crate::vault::serde_helpers::from_slice(&bytes).unwrap();
        assert_eq!(back, envelope);
    }

    // =========================================================================
    // Envelope construction and opening
    // =========================================================================

    use crate::vault::{
        Algorithm, KeyMetadata, KeyRecord, KeyStatus, Origin, Purpose, Timestamp,
        WrappedKeyMaterial,
    };

    const KEK: [u8; 32] = [0x42u8; 32];

    fn make_active_record(algorithm: Algorithm) -> KeyRecord {
        let mut rng = OsRandomSource::new();
        let key_id = KeyId::generate(&mut rng, algorithm.as_str()).unwrap();
        KeyRecord::new(
            KeyMetadata {
                key_id,
                algorithm,
                purpose: match algorithm {
                    Algorithm::Aes256Gcm | Algorithm::ChaCha20Poly1305 => Purpose::Encrypt,
                    _ => Purpose::Sign,
                },
                created_at: Timestamp::from_secs(1_700_000_000),
                created_by: "test".to_string(),
                created_from: Origin::Generated,
                status: KeyStatus::Active,
                version: 1,
                owner: None,
                rotation_due: None,
                expires_at: None,
                parent_key_id: None,
                hardware_backed: false,
                attestation: None,
            },
            WrappedKeyMaterial::Symmetric(vec![0u8; 60]),
        )
    }

    fn lookup_ok(record: KeyRecord) -> impl FnOnce(&KeyId) -> Option<KeyRecord> {
        let id = record.key_id().clone();
        move |asked: &KeyId| {
            if asked == &id { Some(record) } else { None }
        }
    }

    #[test]
    fn envelope_aes_roundtrip() {
        let record = make_active_record(Algorithm::Aes256Gcm);
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let env_bytes = build_envelope(&KEK, &record, plaintext, b"filename.txt".to_vec()).unwrap();
        let opened = open_envelope(&KEK, &env_bytes, lookup_ok(record)).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn envelope_chacha_roundtrip() {
        let record = make_active_record(Algorithm::ChaCha20Poly1305);
        let plaintext = b"some other payload, longer to force multiple blocks";
        let env_bytes = build_envelope(&KEK, &record, plaintext, Vec::new()).unwrap();
        let opened = open_envelope(&KEK, &env_bytes, lookup_ok(record)).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn build_rejects_non_aead_key() {
        let record = make_active_record(Algorithm::Ed25519);
        let err = build_envelope(&KEK, &record, b"data", Vec::new()).unwrap_err();
        assert!(matches!(err, EnvelopeError::WrongCategory { .. }));
    }

    #[test]
    fn build_rejects_non_active_key() {
        let mut record = make_active_record(Algorithm::Aes256Gcm);
        record.metadata.status = KeyStatus::Generated;
        let err = build_envelope(&KEK, &record, b"data", Vec::new()).unwrap_err();
        assert!(matches!(err, EnvelopeError::KeyNotUsable { .. }));
    }

    #[test]
    fn open_rejects_wrong_kek() {
        let record = make_active_record(Algorithm::Aes256Gcm);
        let env_bytes = build_envelope(&KEK, &record, b"data", Vec::new()).unwrap();
        let wrong_kek = [0x43u8; 32];
        let err = open_envelope(&wrong_kek, &env_bytes, lookup_ok(record)).unwrap_err();
        assert!(matches!(err, EnvelopeError::Wrapping(_)));
    }

    #[test]
    fn open_rejects_missing_key() {
        let record = make_active_record(Algorithm::Aes256Gcm);
        let env_bytes = build_envelope(&KEK, &record, b"data", Vec::new()).unwrap();
        let err = open_envelope(&KEK, &env_bytes, |_| None).unwrap_err();
        assert!(matches!(err, EnvelopeError::KeyNotFound(_)));
    }

    #[test]
    fn open_rejects_tampered_header() {
        let record = make_active_record(Algorithm::Aes256Gcm);
        let env_bytes = build_envelope(&KEK, &record, b"payload", b"meta".to_vec()).unwrap();

        // Parse, flip a metadata byte, re-serialize.
        let mut env: Envelope = crate::vault::serde_helpers::from_slice(&env_bytes).unwrap();
        env.header.metadata[0] ^= 0x01;
        let tampered = crate::vault::serde_helpers::to_vec(&env).unwrap();

        let err = open_envelope(&KEK, &tampered, lookup_ok(record)).unwrap_err();
        assert!(matches!(err, EnvelopeError::Aead(_)));
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let record = make_active_record(Algorithm::Aes256Gcm);
        let env_bytes = build_envelope(&KEK, &record, b"payload", Vec::new()).unwrap();

        let mut env: Envelope = crate::vault::serde_helpers::from_slice(&env_bytes).unwrap();
        let mut ct = env.ciphertext.into_vec();
        ct[0] ^= 0x01;
        env.ciphertext = ByteBuf::from(ct);
        let tampered = crate::vault::serde_helpers::to_vec(&env).unwrap();

        let err = open_envelope(&KEK, &tampered, lookup_ok(record)).unwrap_err();
        assert!(matches!(err, EnvelopeError::Aead(_)));
    }

    #[test]
    fn open_rejects_destroyed_key() {
        let mut record = make_active_record(Algorithm::Aes256Gcm);
        let env_bytes = build_envelope(&KEK, &record, b"data", Vec::new()).unwrap();
        record.metadata.status = KeyStatus::Destroyed;

        let err = open_envelope(&KEK, &env_bytes, lookup_ok(record)).unwrap_err();
        assert!(matches!(err, EnvelopeError::KeyNotUsable { .. }));
    }

    #[test]
    fn open_accepts_retired_key() {
        let mut record = make_active_record(Algorithm::Aes256Gcm);
        let env_bytes = build_envelope(&KEK, &record, b"data", Vec::new()).unwrap();
        record.metadata.status = KeyStatus::Retired;

        let opened = open_envelope(&KEK, &env_bytes, lookup_ok(record)).unwrap();
        assert_eq!(opened.as_slice(), b"data");
    }

    #[test]
    fn open_accepts_revoked_key() {
        let mut record = make_active_record(Algorithm::Aes256Gcm);
        let env_bytes = build_envelope(&KEK, &record, b"data", Vec::new()).unwrap();
        record.metadata.status = KeyStatus::Revoked;

        let opened = open_envelope(&KEK, &env_bytes, lookup_ok(record)).unwrap();
        assert_eq!(opened.as_slice(), b"data");
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let record = make_active_record(Algorithm::Aes256Gcm);
        let env_bytes = build_envelope(&KEK, &record, b"", Vec::new()).unwrap();
        let opened = open_envelope(&KEK, &env_bytes, lookup_ok(record)).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn metadata_is_authenticated_but_not_encrypted() {
        let record = make_active_record(Algorithm::Aes256Gcm);
        let meta = b"original-filename.pdf".to_vec();
        let env_bytes = build_envelope(&KEK, &record, b"payload", meta.clone()).unwrap();

        // Metadata is visible without the KEK: just parse the envelope.
        let env: Envelope = crate::vault::serde_helpers::from_slice(&env_bytes).unwrap();
        assert_eq!(env.header.metadata, meta);
    }

    #[test]
    fn envelope_binds_to_key_id() {
        let record = make_active_record(Algorithm::Aes256Gcm);
        let env_bytes = build_envelope(&KEK, &record, b"payload", Vec::new()).unwrap();

        // Swap in a different record with the same KEK but another id.
        let other = make_active_record(Algorithm::Aes256Gcm);
        let err = open_envelope(&KEK, &env_bytes, lookup_ok(other)).unwrap_err();
        assert!(matches!(err, EnvelopeError::KeyNotFound(_)));
    }
}

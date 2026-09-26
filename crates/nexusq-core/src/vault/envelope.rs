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

use crate::crypto::aead::Algorithm as AeadAlgorithm;

use super::key_id::KeyId;

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
}

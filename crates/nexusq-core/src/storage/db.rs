//! Storage database (format F-03).
//!
//! An append-only index of records with a CRC per record and a CRC
//! over the whole file. It holds pointers and metadata, never secret
//! material: the vault keeps keys, envelopes keep ciphertext, and the
//! storage database keeps the map.
//!
//! ## Layout
//!
//! ```text
//! [magic: 4 bytes "NQS1"]
//! [version: 1 byte]
//! [record count: 8 bytes, big-endian]
//! [record 0: length-prefixed]
//! [record 1: length-prefixed]
//! ...
//! [trailer CRC: 4 bytes, big-endian]
//! ```
//!
//! Each record is:
//!
//! ```text
//! [kind: 1 byte]
//! [key length: 4 bytes, BE]
//! [key bytes]
//! [value length: 4 bytes, BE]
//! [value bytes]
//! [record CRC: 4 bytes, BE, over kind || key || value]
//! ```
//!
//! The trailer CRC covers every record's bytes in order, from the
//! first kind byte to the last value byte. The per-record CRCs
//! detect local corruption; the trailer detects truncation and
//! reordering.
//!
//! ## What this is not
//!
//! This database is **not encrypted**. It must not contain secrets.
//! If a value happens to be sensitive (for example, a filename the
//! user considers private), the caller encrypts it before storing.
//!
//! See `docs/STORAGE.md` §6.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File magic for the storage database.
pub const MAGIC: [u8; 4] = *b"NQS1";

/// Current format version.
pub const FORMAT_VERSION: u8 = 1;

/// Maximum key length we accept, in bytes.
///
/// The limit exists to bound the work a malformed file can cause. It
/// is generous: 64 KiB covers any realistic key.
pub const MAX_KEY_LEN: u32 = 64 * 1024;

/// Maximum value length we accept, in bytes.
pub const MAX_VALUE_LEN: u32 = 16 * 1024 * 1024;

/// Category of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RecordKind {
    /// Index entry for a key: maps a KeyId to non-secret metadata.
    KeyIndex = 1,
    /// Index entry for an envelope: maps an envelope id to metadata.
    EnvelopeIndex = 2,
    /// Configuration snapshot.
    Config = 3,
}

impl RecordKind {
    /// Returns the byte used on disk.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Converts a byte from disk.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::UnknownKind`] for any value not defined.
    pub const fn from_byte(b: u8) -> Result<Self, DbError> {
        match b {
            1 => Ok(Self::KeyIndex),
            2 => Ok(Self::EnvelopeIndex),
            3 => Ok(Self::Config),
            other => Err(DbError::UnknownKind(other)),
        }
    }
}

/// One entry in the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Category of the record.
    pub kind: RecordKind,
    /// Lookup key, opaque to the database.
    pub key: Vec<u8>,
    /// Value, opaque to the database.
    pub value: Vec<u8>,
}

/// Errors returned by storage database operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DbError {
    /// An I/O error occurred.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The file was too short to contain a valid header.
    #[error("file too short")]
    TooShort,

    /// The magic number was not [`MAGIC`].
    #[error("invalid magic number")]
    BadMagic,

    /// The version byte was not recognized.
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u8),

    /// A record was missing bytes or had an inconsistent length.
    #[error("malformed record")]
    MalformedRecord,

    /// A per-record CRC did not match the data.
    #[error("record CRC mismatch")]
    RecordCrcMismatch,

    /// The trailer CRC did not match the records.
    #[error("trailer CRC mismatch")]
    TrailerCrcMismatch,

    /// A record kind byte was not recognized.
    #[error("unknown record kind: {0}")]
    UnknownKind(u8),

    /// A key or value exceeded the accepted length.
    #[error("length limit exceeded")]
    LengthLimitExceeded,
}

/// An in-memory index with on-disk persistence.
///
/// Records are stored sorted by `(kind, key)`. The map is a
/// `BTreeMap` so iteration is deterministic, which matters because the
/// trailer CRC is computed over the file in order.
#[derive(Debug, Clone, Default)]
pub struct StorageDb {
    records: BTreeMap<(RecordKind, Vec<u8>), Vec<u8>>,
}

impl StorageDb {
    /// Creates an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if the database contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Inserts or replaces a record.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::LengthLimitExceeded`] if the key or value
    /// exceeds the accepted limits.
    pub fn insert(
        &mut self,
        kind: RecordKind,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), DbError> {
        let key = key.into();
        let value = value.into();
        if key.len() as u64 > MAX_KEY_LEN as u64 {
            return Err(DbError::LengthLimitExceeded);
        }
        if value.len() as u64 > MAX_VALUE_LEN as u64 {
            return Err(DbError::LengthLimitExceeded);
        }
        self.records.insert((kind, key), value);
        Ok(())
    }

    /// Returns the value stored under `(kind, key)`, if any.
    #[must_use]
    pub fn get(&self, kind: RecordKind, key: &[u8]) -> Option<&[u8]> {
        self.records.get(&(kind, key.to_vec())).map(Vec::as_slice)
    }

    /// Removes a record, returning `true` if it existed.
    pub fn remove(&mut self, kind: RecordKind, key: &[u8]) -> bool {
        self.records.remove(&(kind, key.to_vec())).is_some()
    }

    /// Iterates over the keys of every record of the given kind.
    pub fn keys(&self, kind: RecordKind) -> impl Iterator<Item = &[u8]> {
        self.records
            .iter()
            .filter(move |((k, _), _)| *k == kind)
            .map(|((_, key), _)| key.as_slice())
    }

    /// Iterates over every `(key, value)` pair of the given kind.
    pub fn entries(&self, kind: RecordKind) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.records
            .iter()
            .filter(move |((k, _), _)| *k == kind)
            .map(|((_, key), value)| (key.as_slice(), value.as_slice()))
    }

    // =========================================================================
    // Serialization
    // =========================================================================

    /// Serializes the database to the F-03 wire format.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::LengthLimitExceeded`] if any key or value
    /// exceeds the accepted limits (should not happen for records
    /// inserted through [`StorageDb::insert`], but the check is
    /// repeated here for safety).
    pub fn to_bytes(&self) -> Result<Vec<u8>, DbError> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&(self.records.len() as u64).to_be_bytes());

        let mut trailer = Vec::new();
        for ((kind, key), value) in &self.records {
            if key.len() as u64 > MAX_KEY_LEN as u64 || value.len() as u64 > MAX_VALUE_LEN as u64 {
                return Err(DbError::LengthLimitExceeded);
            }

            // Bytes covered by the per-record CRC.
            let mut payload = Vec::with_capacity(1 + key.len() + value.len());
            payload.push(kind.as_byte());
            payload.extend_from_slice(key);
            payload.extend_from_slice(value);

            let record_crc = crc32c::crc32c(&payload);

            // Wire form: kind, key len, key, value len, value, crc.
            out.push(kind.as_byte());
            out.extend_from_slice(&(key.len() as u32).to_be_bytes());
            out.extend_from_slice(key);
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
            out.extend_from_slice(&record_crc.to_be_bytes());

            // Trailer covers the payload only, not the length fields
            // or per-record CRC. This keeps the trailer meaningful
            // even if the wire format changes slightly.
            trailer.extend_from_slice(&payload);
        }

        let trailer_crc = crc32c::crc32c(&trailer);
        out.extend_from_slice(&trailer_crc.to_be_bytes());
        Ok(out)
    }

    /// Parses the F-03 wire format.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`DbError`] for the first failed
    /// check: short file, bad magic, unknown version, malformed
    /// record, record CRC mismatch, trailer CRC mismatch, or unknown
    /// kind.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DbError> {
        // Header: magic (4) + version (1) + count (8).
        const HEADER_LEN: usize = 4 + 1 + 8;
        const TRAILER_LEN: usize = 4;

        if bytes.len() < HEADER_LEN + TRAILER_LEN {
            return Err(DbError::TooShort);
        }
        if bytes[..4] != MAGIC {
            return Err(DbError::BadMagic);
        }
        let version = bytes[4];
        if version != FORMAT_VERSION {
            return Err(DbError::UnsupportedVersion(version));
        }
        let count = u64::from_be_bytes(
            bytes[5..13]
                .try_into()
                .expect("slice of 8 bytes by construction"),
        ) as usize;

        // Parse records up to the trailer.
        let body_start = HEADER_LEN;
        let body_end = bytes.len() - TRAILER_LEN;
        let body = &bytes[body_start..body_end];

        let mut records = BTreeMap::new();
        let mut trailer = Vec::new();
        let mut cursor = 0;

        for _ in 0..count {
            // kind (1)
            if cursor + 1 > body.len() {
                return Err(DbError::MalformedRecord);
            }
            let kind_byte = body[cursor];
            let kind = RecordKind::from_byte(kind_byte)?;
            cursor += 1;

            // key len (4)
            if cursor + 4 > body.len() {
                return Err(DbError::MalformedRecord);
            }
            let key_len =
                u32::from_be_bytes(body[cursor..cursor + 4].try_into().expect("4 bytes")) as usize;
            cursor += 4;
            if key_len as u64 > MAX_KEY_LEN as u64 {
                return Err(DbError::LengthLimitExceeded);
            }

            // key
            if cursor + key_len > body.len() {
                return Err(DbError::MalformedRecord);
            }
            let key = body[cursor..cursor + key_len].to_vec();
            cursor += key_len;

            // value len (4)
            if cursor + 4 > body.len() {
                return Err(DbError::MalformedRecord);
            }
            let value_len =
                u32::from_be_bytes(body[cursor..cursor + 4].try_into().expect("4 bytes")) as usize;
            cursor += 4;
            if value_len as u64 > MAX_VALUE_LEN as u64 {
                return Err(DbError::LengthLimitExceeded);
            }

            // value
            if cursor + value_len > body.len() {
                return Err(DbError::MalformedRecord);
            }
            let value = body[cursor..cursor + value_len].to_vec();
            cursor += value_len;

            // per-record crc (4)
            if cursor + 4 > body.len() {
                return Err(DbError::MalformedRecord);
            }
            let stored_crc =
                u32::from_be_bytes(body[cursor..cursor + 4].try_into().expect("4 bytes"));
            cursor += 4;

            // Verify the per-record CRC.
            let mut payload = Vec::with_capacity(1 + key.len() + value.len());
            payload.push(kind_byte);
            payload.extend_from_slice(&key);
            payload.extend_from_slice(&value);
            let computed_crc = crc32c::crc32c(&payload);
            if computed_crc != stored_crc {
                return Err(DbError::RecordCrcMismatch);
            }

            trailer.extend_from_slice(&payload);
            records.insert((kind, key), value);
        }

        if cursor != body.len() {
            return Err(DbError::MalformedRecord);
        }

        // Verify the trailer CRC.
        let stored_trailer = u32::from_be_bytes(
            bytes[body_end..]
                .try_into()
                .expect("slice of 4 bytes by construction"),
        );
        let computed_trailer = crc32c::crc32c(&trailer);
        if computed_trailer != stored_trailer {
            return Err(DbError::TrailerCrcMismatch);
        }

        Ok(Self { records })
    }

    // =========================================================================
    // File operations
    // =========================================================================

    /// Reads a database from disk.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Io`] if the file cannot be read, or any
    /// parse error from [`StorageDb::from_bytes`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Writes the database to disk atomically.
    ///
    /// The file is written to a temporary name next to the target and
    /// then renamed, so readers never observe a partially written
    /// database.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Io`] if the write or rename fails, or a
    /// serialization error from [`StorageDb::to_bytes`].
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let path = path.as_ref();
        let bytes = self.to_bytes()?;
        let tmp = temp_path(path);
        fs::write(&tmp, &bytes)?;
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(DbError::Io(e));
        }
        Ok(())
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn kind_roundtrips_through_byte() {
        for kind in [
            RecordKind::KeyIndex,
            RecordKind::EnvelopeIndex,
            RecordKind::Config,
        ] {
            assert_eq!(RecordKind::from_byte(kind.as_byte()).unwrap(), kind);
        }
    }

    #[test]
    fn unknown_kind_byte_fails() {
        assert!(matches!(
            RecordKind::from_byte(99),
            Err(DbError::UnknownKind(99))
        ));
    }

    #[test]
    fn new_db_is_empty() {
        let db = StorageDb::new();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
    }

    #[test]
    fn insert_and_get_roundtrip() {
        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"k1", b"v1").unwrap();
        assert_eq!(db.get(RecordKind::KeyIndex, b"k1"), Some(&b"v1"[..]));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn insert_replaces_existing_record() {
        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"k1", b"v1").unwrap();
        db.insert(RecordKind::KeyIndex, b"k1", b"v2").unwrap();
        assert_eq!(db.get(RecordKind::KeyIndex, b"k1"), Some(&b"v2"[..]));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn get_returns_none_for_missing() {
        let db = StorageDb::new();
        assert!(db.get(RecordKind::KeyIndex, b"nope").is_none());
    }

    #[test]
    fn remove_returns_true_only_if_present() {
        let mut db = StorageDb::new();
        assert!(!db.remove(RecordKind::KeyIndex, b"k1"));
        db.insert(RecordKind::KeyIndex, b"k1", b"v1").unwrap();
        assert!(db.remove(RecordKind::KeyIndex, b"k1"));
        assert!(db.is_empty());
    }

    #[test]
    fn keys_filters_by_kind() {
        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"a", b"1").unwrap();
        db.insert(RecordKind::KeyIndex, b"b", b"2").unwrap();
        db.insert(RecordKind::EnvelopeIndex, b"c", b"3").unwrap();

        let keys: Vec<_> = db.keys(RecordKind::KeyIndex).collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn entries_yields_pairs_of_the_right_kind() {
        let mut db = StorageDb::new();
        db.insert(RecordKind::Config, b"theme", b"dark").unwrap();
        db.insert(RecordKind::KeyIndex, b"k", b"v").unwrap();

        let entries: Vec<_> = db.entries(RecordKind::Config).collect();
        assert_eq!(entries, vec![(&b"theme"[..], &b"dark"[..])]);
    }

    #[test]
    fn to_bytes_then_from_bytes_roundtrip() {
        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"k1", b"v1").unwrap();
        db.insert(RecordKind::KeyIndex, b"k2", b"value with spaces")
            .unwrap();
        db.insert(RecordKind::Config, b"theme", b"dark").unwrap();

        let bytes = db.to_bytes().unwrap();
        let back = StorageDb::from_bytes(&bytes).unwrap();

        assert_eq!(back.len(), db.len());
        for ((kind, key), value) in &db.records {
            assert_eq!(back.get(*kind, key), Some(value.as_slice()));
        }
    }

    #[test]
    fn from_bytes_rejects_short_input() {
        let bytes = b"NQS1";
        assert!(matches!(
            StorageDb::from_bytes(bytes),
            Err(DbError::TooShort)
        ));
    }

    #[test]
    fn from_bytes_rejects_bad_magic() {
        let mut bytes = vec![0u8; 20];
        bytes[..4].copy_from_slice(b"XXXX");
        assert!(matches!(
            StorageDb::from_bytes(&bytes),
            Err(DbError::BadMagic)
        ));
    }

    #[test]
    fn from_bytes_rejects_unknown_version() {
        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"k", b"v").unwrap();
        let mut bytes = db.to_bytes().unwrap();
        bytes[4] = 99;
        assert!(matches!(
            StorageDb::from_bytes(&bytes),
            Err(DbError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn from_bytes_detects_record_crc_mismatch() {
        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"k", b"v").unwrap();
        let mut bytes = db.to_bytes().unwrap();
        // Flip a byte in the key region (after header).
        // Layout: magic(4) + version(1) + count(8) + kind(1) + keylen(4) + key...
        let key_offset = 4 + 1 + 8 + 1 + 4;
        bytes[key_offset] ^= 0x01;
        assert!(matches!(
            StorageDb::from_bytes(&bytes),
            Err(DbError::RecordCrcMismatch)
        ));
    }

    #[test]
    fn from_bytes_detects_trailer_crc_mismatch() {
        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"k", b"v").unwrap();
        let mut bytes = db.to_bytes().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(matches!(
            StorageDb::from_bytes(&bytes),
            Err(DbError::TrailerCrcMismatch)
        ));
    }

    #[test]
    fn from_bytes_detects_truncation() {
        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"key", b"value").unwrap();
        let mut bytes = db.to_bytes().unwrap();
        bytes.truncate(bytes.len() - 5);
        assert!(matches!(
            StorageDb::from_bytes(&bytes),
            Err(DbError::MalformedRecord)
                | Err(DbError::TrailerCrcMismatch)
                | Err(DbError::TooShort)
        ));
    }

    #[test]
    fn insert_rejects_oversized_key() {
        let mut db = StorageDb::new();
        let big_key = vec![0u8; (MAX_KEY_LEN + 1) as usize];
        assert!(matches!(
            db.insert(RecordKind::KeyIndex, big_key, b"v".to_vec()),
            Err(DbError::LengthLimitExceeded)
        ));
    }

    #[test]
    fn file_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("index.nqs");

        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"k1", b"v1").unwrap();
        db.insert(RecordKind::Config, b"theme", b"dark").unwrap();
        db.save(&path).unwrap();

        let back = StorageDb::open(&path).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.get(RecordKind::KeyIndex, b"k1"), Some(&b"v1"[..]));
        assert_eq!(back.get(RecordKind::Config, b"theme"), Some(&b"dark"[..]));
    }

    #[test]
    fn save_leaves_no_temp_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("index.nqs");

        let mut db = StorageDb::new();
        db.insert(RecordKind::KeyIndex, b"k", b"v").unwrap();
        db.save(&path).unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["index.nqs"]);
    }
}

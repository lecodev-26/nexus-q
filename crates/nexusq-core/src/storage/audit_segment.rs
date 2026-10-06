//! Audit segments (format F-04).
//!
//! A segment is an append-only file that holds a list of chained
//! [`AuditEvent`]s, plus the identifier of the segment and the hash of
//! the previous segment. Segments chain to each other: the first
//! segment's `prev_segment` is all zeros, and every later segment
//! carries the `segment_hash` of its predecessor.
//!
//! ## Wire format
//!
//! ```text
//! [magic \"NQA2\"]
//! [version 1]
//! [segment_id 16 bytes]
//! [prev_segment 32 bytes]
//! [event_count u32 BE]
//! [event]* (each length-prefixed, CBOR)
//! [segment_hash 32 bytes]
//! ```
//!
//! Each event is stored as:
//!
//! ```text
//! [event_len u32 BE][event CBOR bytes]
//! ```
//!
//! ## Segment hash
//!
//! ```text
//! segment_hash = HMAC-SHA256(audit_key, prev_segment || last_event_hash)
//! ```
//!
//! For an empty segment, `last_event_hash` is omitted and the hash is
//! `HMAC-SHA256(audit_key, prev_segment)`.
//!
//! Modifying any event breaks its own hash, which breaks the segment
//! hash, which breaks the next segment's `prev_segment` link.
//!
//! See `docs/STORAGE.md` §7 and `docs/SECURITY_MODEL.md` §7.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::random::{OsRandomSource, RandomError, RandomSource};
use crate::vault::Timestamp;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::audit_event::{AuditEvent, AuditEventSpec, GENESIS_HASH, HASH_LEN};
use super::db::DbError;

/// File magic for the audit segment format.
pub const MAGIC: [u8; 4] = *b"NQA2";

/// Current format version.
pub const FORMAT_VERSION: u8 = 2;

/// Length in bytes of a segment identifier.
pub const SEGMENT_ID_LEN: usize = 16;

/// Maximum length of a single serialized event, in bytes.
pub const MAX_EVENT_LEN: u32 = 1024 * 1024;

/// A unique identifier for a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SegmentId([u8; SEGMENT_ID_LEN]);

impl SegmentId {
    /// All-zero identifier, used as the default.
    pub const ZERO: Self = Self([0u8; SEGMENT_ID_LEN]);

    /// Generates a fresh random identifier.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Io`] if the OS random source fails.
    pub fn generate() -> Result<Self, DbError> {
        let mut bytes = [0u8; SEGMENT_ID_LEN];
        let source = OsRandomSource::new();
        source
            .fill_bytes(&mut bytes)
            .map_err(|_: RandomError| DbError::Io(std::io::Error::other("rng failure")))?;
        Ok(Self(bytes))
    }

    /// Wraps raw bytes as an identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SEGMENT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SEGMENT_ID_LEN] {
        &self.0
    }
}

impl std::fmt::Display for SegmentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A segment: a file holding a chain of events.
#[derive(Clone)]
pub struct AuditSegment {
    id: SegmentId,
    prev_segment: [u8; HASH_LEN],
    events: Vec<AuditEvent>,
    auth_key: Zeroizing<[u8; HASH_LEN]>,
    stored_hash: [u8; HASH_LEN],
}

impl AuditSegment {
    /// Creates a new, empty segment.
    ///
    /// Pass `None` for `prev_segment` to start the first segment of a
    /// chain; the previous-segment hash is then all zeros.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Io`] if the OS random source fails while
    /// generating the segment id.
    pub fn new(prev_segment: Option<[u8; HASH_LEN]>) -> Result<Self, DbError> {
        Self::new_with_key(prev_segment, &[0u8; HASH_LEN])
    }

    pub fn new_with_key(
        prev_segment: Option<[u8; HASH_LEN]>,
        auth_key: &[u8; HASH_LEN],
    ) -> Result<Self, DbError> {
        let prev_segment = prev_segment.unwrap_or(GENESIS_HASH);
        let auth_key = Zeroizing::new(*auth_key);
        let stored_hash = authenticate_segment(auth_key.as_ref(), &prev_segment);
        Ok(Self {
            id: SegmentId::generate()?,
            prev_segment,
            events: Vec::new(),
            auth_key,
            stored_hash,
        })
    }

    /// Returns the segment's identifier.
    #[must_use]
    pub const fn id(&self) -> SegmentId {
        self.id
    }

    /// Returns the hash of the previous segment.
    #[must_use]
    pub const fn prev_segment(&self) -> &[u8; HASH_LEN] {
        &self.prev_segment
    }

    /// Returns the number of events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the segment has no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns the events.
    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Appends a new event to the segment.
    ///
    /// The event index is assigned automatically: it is the previous
    /// last index plus one, or 1 if the segment is empty. The
    /// `prev_hash` is set to the hash of the previous event, or
    /// [`GENESIS_HASH`] if this is the first event in the segment.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::MalformedRecord`] if hashing fails.
    pub fn append(
        &mut self,
        timestamp: Timestamp,
        spec: AuditEventSpec,
    ) -> Result<&AuditEvent, DbError> {
        let index = self.events.last().map_or(1, |e| e.index + 1);
        let prev_hash = self
            .events
            .last()
            .map_or_else(|| GENESIS_HASH.to_vec(), |e| e.hash.clone());

        let event = AuditEvent::new(index, timestamp, spec, &prev_hash, &*self.auth_key)?;
        self.events.push(event);
        self.stored_hash = self.segment_hash()?;
        Ok(self.events.last().expect("just pushed"))
    }

    /// Returns the segment hash.
    ///
    /// # Errors
    ///
    /// This function cannot currently fail; it returns a `Result` to
    /// match the shape of other hashing helpers and to leave room for
    /// a fallible hasher in the future.
    pub fn segment_hash(&self) -> Result<[u8; HASH_LEN], DbError> {
        let mut buf = Vec::with_capacity(HASH_LEN + HASH_LEN);
        buf.extend_from_slice(&self.prev_segment);
        if let Some(last) = self.events.last() {
            buf.extend_from_slice(&last.hash);
        }
        Ok(authenticate_segment(&*self.auth_key, &buf))
    }

    /// Verifies the whole chain:
    ///
    /// - every event's stored hash matches a fresh computation;
    /// - every event's `prev_hash` matches the previous event's hash
    ///   (or [`GENESIS_HASH`] for the first);
    /// - indices are strictly increasing from 1.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::RecordCrcMismatch`] if any check fails.
    pub fn verify(&self) -> Result<(), DbError> {
        let mut expected_prev: Vec<u8> = GENESIS_HASH.to_vec();

        for (expected_index, event) in (1_u64..).zip(self.events.iter()) {
            if event.index != expected_index {
                return Err(DbError::RecordCrcMismatch);
            }
            if event.prev_hash != expected_prev {
                return Err(DbError::RecordCrcMismatch);
            }
            if !event.is_intact(&*self.auth_key)? {
                return Err(DbError::RecordCrcMismatch);
            }
            expected_prev.clone_from(&event.hash);
        }

        if self.segment_hash()? != self.stored_hash {
            return Err(DbError::TrailerCrcMismatch);
        }
        Ok(())
    }

    // =========================================================================
    // Serialization
    // =========================================================================

    /// Serializes the segment to the F-04 wire format.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::MalformedRecord`] if a serialized event
    /// exceeds [`MAX_EVENT_LEN`], or [`DbError::Io`] if CBOR fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DbError> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.prev_segment);

        let count = u32::try_from(self.events.len()).map_err(|_| DbError::LengthLimitExceeded)?;
        out.extend_from_slice(&count.to_be_bytes());

        for event in &self.events {
            let event_bytes = crate::vault::to_vec(event).map_err(|_| DbError::MalformedRecord)?;
            if event_bytes.len() as u64 > MAX_EVENT_LEN as u64 {
                return Err(DbError::LengthLimitExceeded);
            }
            let len = u32::try_from(event_bytes.len()).map_err(|_| DbError::LengthLimitExceeded)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&event_bytes);
        }

        let hash = self.segment_hash()?;
        out.extend_from_slice(&hash);
        Ok(out)
    }

    /// Parses the F-04 wire format.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`DbError`] for the first failed
    /// check: too short, bad magic, unknown version, malformed event,
    /// or segment hash mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DbError> {
        // Header: magic (4) + version (1) + id (16) + prev (32) + count (4)
        const HEADER_LEN: usize = 4 + 1 + SEGMENT_ID_LEN + HASH_LEN + 4;
        const TRAILER_LEN: usize = HASH_LEN;

        if bytes.len() < HEADER_LEN + TRAILER_LEN {
            return Err(DbError::TooShort);
        }
        if bytes[..4] != MAGIC {
            return Err(DbError::BadMagic);
        }
        if bytes[4] != FORMAT_VERSION {
            return Err(DbError::UnsupportedVersion(bytes[4]));
        }

        let mut id_bytes = [0u8; SEGMENT_ID_LEN];
        id_bytes.copy_from_slice(&bytes[5..5 + SEGMENT_ID_LEN]);
        let id = SegmentId::from_bytes(id_bytes);

        let mut prev_segment = [0u8; HASH_LEN];
        prev_segment.copy_from_slice(&bytes[5 + SEGMENT_ID_LEN..5 + SEGMENT_ID_LEN + HASH_LEN]);

        let count_offset = 5 + SEGMENT_ID_LEN + HASH_LEN;
        let count = u32::from_be_bytes(
            bytes[count_offset..count_offset + 4]
                .try_into()
                .expect("4 bytes"),
        ) as usize;

        let body_start = HEADER_LEN;
        let body_end = bytes.len() - TRAILER_LEN;
        let body = &bytes[body_start..body_end];

        let mut events = Vec::with_capacity(count);
        let mut cursor = 0;
        for _ in 0..count {
            if cursor + 4 > body.len() {
                return Err(DbError::MalformedRecord);
            }
            let event_len =
                u32::from_be_bytes(body[cursor..cursor + 4].try_into().expect("4 bytes")) as usize;
            cursor += 4;
            if event_len as u64 > MAX_EVENT_LEN as u64 {
                return Err(DbError::LengthLimitExceeded);
            }
            if cursor + event_len > body.len() {
                return Err(DbError::MalformedRecord);
            }
            let event: AuditEvent = crate::vault::from_slice(&body[cursor..cursor + event_len])
                .map_err(|_| DbError::MalformedRecord)?;
            cursor += event_len;
            events.push(event);
        }
        if cursor != body.len() {
            return Err(DbError::MalformedRecord);
        }

        let mut stored_hash = [0u8; HASH_LEN];
        stored_hash.copy_from_slice(&bytes[body_end..]);

        let segment = Self {
            id,
            prev_segment,
            events,
            auth_key: Zeroizing::new([0u8; HASH_LEN]),
            stored_hash,
        };
        Ok(segment)
    }

    // =========================================================================
    // File operations
    // =========================================================================

    /// Reads a segment from disk.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Io`] if the file cannot be read, or any
    /// parse error from [`AuditSegment::from_bytes`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Installs the vault-derived authentication key for verification and
    /// subsequent appends.
    pub fn set_auth_key(&mut self, auth_key: &[u8; HASH_LEN]) {
        self.auth_key = Zeroizing::new(*auth_key);
    }

    /// Writes the segment to disk atomically.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Io`] if the write or rename fails, or a
    /// serialization error from [`AuditSegment::to_bytes`].
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

fn authenticate_segment(key: &[u8; HASH_LEN], data: &[u8]) -> [u8; HASH_LEN] {
    const BLOCK: usize = 64;
    let mut key_block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..HASH_LEN].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for byte in key_block.iter() {
        inner.update([*byte ^ 0x36]);
    }
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    for byte in key_block.iter() {
        outer.update([*byte ^ 0x5c]);
    }
    outer.update(inner_hash);
    outer.finalize().into()
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; HASH_LEN] = [0x42; HASH_LEN];
    use crate::storage::audit_event::{EventOutcome, EventType};
    use tempfile::TempDir;

    fn ts(n: u64) -> Timestamp {
        Timestamp::from_secs(1_700_000_000 + n)
    }

    fn spec(kind: EventType) -> AuditEventSpec {
        AuditEventSpec::new(kind)
            .with_actor("test")
            .with_subject("subject")
    }

    #[test]
    fn new_segment_is_empty_with_genesis_prev() {
        let seg = AuditSegment::new(None).unwrap();
        assert!(seg.is_empty());
        assert_eq!(seg.prev_segment(), &GENESIS_HASH);
    }

    #[test]
    fn new_segment_can_set_prev_segment() {
        let prev = [0xAAu8; HASH_LEN];
        let seg = AuditSegment::new(Some(prev)).unwrap();
        assert_eq!(seg.prev_segment(), &prev);
    }

    #[test]
    fn append_assigns_monotonic_indices() {
        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        seg.append(ts(2), spec(EventType::KeyUsed)).unwrap();
        seg.append(ts(3), spec(EventType::KeyRotated)).unwrap();
        assert_eq!(seg.len(), 3);
        assert_eq!(seg.events()[0].index, 1);
        assert_eq!(seg.events()[1].index, 2);
        assert_eq!(seg.events()[2].index, 3);
    }

    #[test]
    fn append_links_hashes() {
        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        seg.append(ts(2), spec(EventType::KeyUsed)).unwrap();

        assert_eq!(seg.events()[0].prev_hash, GENESIS_HASH.to_vec());
        assert_eq!(seg.events()[1].prev_hash, seg.events()[0].hash);
    }

    #[test]
    fn verify_accepts_fresh_segment() {
        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        seg.append(ts(2), spec(EventType::KeyUsed)).unwrap();
        assert!(seg.verify().is_ok());
    }

    #[test]
    fn verify_rejects_tampered_event() {
        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        seg.append(ts(2), spec(EventType::KeyUsed)).unwrap();

        // Tamper directly.
        seg.events[0].actor = "someone-else".into();
        assert!(matches!(seg.verify(), Err(DbError::RecordCrcMismatch)));
    }

    #[test]
    fn segment_hash_is_stable_across_calls() {
        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        let a = seg.segment_hash().unwrap();
        let b = seg.segment_hash().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_segment_hash_matches_formula() {
        let seg = AuditSegment::new(None).unwrap();
        let expected = sha256(&GENESIS_HASH);
        assert_eq!(seg.segment_hash().unwrap(), expected);
    }

    #[test]
    fn different_prev_segment_changes_segment_hash() {
        let mut a = AuditSegment::new(None).unwrap();
        a.append(ts(1), spec(EventType::KeyCreated)).unwrap();

        let mut b = AuditSegment::new(Some([0xAA; HASH_LEN])).unwrap();
        b.append(ts(1), spec(EventType::KeyCreated)).unwrap();

        assert_ne!(a.segment_hash().unwrap(), b.segment_hash().unwrap());
    }

    #[test]
    fn to_bytes_then_from_bytes_roundtrip() {
        let mut seg = AuditSegment::new(Some([0x42; HASH_LEN])).unwrap();
        seg.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        seg.append(ts(2), spec(EventType::KeyUsed)).unwrap();

        let bytes = seg.to_bytes().unwrap();
        let back = AuditSegment::from_bytes(&bytes).unwrap();

        assert_eq!(back.id(), seg.id());
        assert_eq!(back.prev_segment(), seg.prev_segment());
        assert_eq!(back.len(), seg.len());
        assert!(back.verify().is_ok());
        assert_eq!(back.segment_hash().unwrap(), seg.segment_hash().unwrap());
    }

    #[test]
    fn from_bytes_rejects_short_input() {
        assert!(matches!(
            AuditSegment::from_bytes(b"NQA2"),
            Err(DbError::TooShort)
        ));
    }

    #[test]
    fn from_bytes_rejects_bad_magic() {
        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        let mut bytes = seg.to_bytes().unwrap();
        bytes[..4].copy_from_slice(b"XXXX");
        assert!(matches!(
            AuditSegment::from_bytes(&bytes),
            Err(DbError::BadMagic)
        ));
    }

    #[test]
    fn from_bytes_rejects_unknown_version() {
        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        let mut bytes = seg.to_bytes().unwrap();
        bytes[4] = 99;
        assert!(matches!(
            AuditSegment::from_bytes(&bytes),
            Err(DbError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn from_bytes_detects_tampered_segment_hash() {
        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        let mut bytes = seg.to_bytes().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let back = AuditSegment::from_bytes(&bytes).unwrap();
        assert!(matches!(back.verify(), Err(DbError::TrailerCrcMismatch)));
    }

    #[test]
    fn file_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit-00001.nqa");

        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        seg.append(ts(2), spec(EventType::VaultUnlocked)).unwrap();
        seg.save(&path).unwrap();

        let back = AuditSegment::open(&path).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.verify().is_ok());
    }

    #[test]
    fn save_leaves_no_temp_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.nqa");

        let mut seg = AuditSegment::new(None).unwrap();
        seg.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        seg.save(&path).unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["audit.nqa"]);
    }

    #[test]
    fn segment_id_display_is_hex() {
        let id = SegmentId::from_bytes([0xAB; SEGMENT_ID_LEN]);
        assert_eq!(id.to_string(), "ab".repeat(SEGMENT_ID_LEN));
    }

    #[test]
    fn outcome_field_persists() {
        let mut seg = AuditSegment::new(None).unwrap();
        let s = spec(EventType::KeyAccessDenied).with_outcome(EventOutcome::Denied);
        seg.append(ts(1), s).unwrap();

        let bytes = seg.to_bytes().unwrap();
        let back = AuditSegment::from_bytes(&bytes).unwrap();
        assert_eq!(back.events()[0].outcome, EventOutcome::Denied);
    }
}

//! Audit log manager.
//!
//! An [`AuditLog`] ties together a directory of [`AuditSegment`]s and
//! the append operation. It is what callers interact with: they open
//! the log once, append events as operations happen, and let the log
//! rotate and chain segments automatically.
//!
//! ## Directory layout
//!
//! ```text
//! audit/
//!   audit-00001.nqa
//!   audit-00002.nqa
//!   ...
//! ```
//!
//! Files are named with a five-digit zero-padded number so that
//! lexical order matches numeric order. Anything else in the
//! directory is ignored.
//!
//! ## Rotation
//!
//! When the current segment reaches [`AuditLogConfig::max_events`],
//! the next append rotates: the current segment is finalized, its
//! hash becomes the `prev_segment` of the new one, and the new
//! segment starts empty.
//!
//! ## Durability
//!
//! Every append writes the segment to disk before returning. If the
//! write fails, the append fails and the caller must treat the
//! operation as failed. This is the "failure to log = failure to
//! operate" rule from `docs/SECURITY_MODEL.md` §7.6.
//!
//! ## Performance note
//!
//! Because the F-04 format carries the segment hash in a trailer,
//! appending means rewriting the whole segment. Segments are
//! bounded, so this is acceptable; a future version may adopt an
//! appendable layout with per-event CRCs and a separate index.

use std::fs;
use std::path::{Path, PathBuf};

use crate::vault::Timestamp;

use super::audit_event::{AuditEvent, AuditEventSpec};
use super::audit_segment::{AuditSegment, SegmentId};
use super::db::DbError;

/// Default maximum number of events per segment.
pub const DEFAULT_MAX_EVENTS: usize = 1000;

/// Tuning for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditLogConfig {
    /// Rotate when a segment reaches this many events.
    pub max_events: usize,
}

impl Default for AuditLogConfig {
    fn default() -> Self {
        Self {
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

/// A directory of segments plus the current one.
#[derive(Debug)]
pub struct AuditLog {
    dir: PathBuf,
    current: AuditSegment,
    current_path: PathBuf,
    current_number: u32,
    config: AuditLogConfig,
}

impl AuditLog {
    /// Opens the log in `dir`, creating the first segment if the
    /// directory is empty.
    ///
    /// The directory must already exist. An empty directory is
    /// initialized with `audit-00001.nqa`; a populated one continues
    /// from the highest-numbered segment.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Io`] if the directory cannot be read or
    /// written, [`DbError::NotFound`] is not applicable here (we
    /// never look up by name), and any parse error from the segment
    /// being opened.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, DbError> {
        Self::open_with(dir, AuditLogConfig::default())
    }

    /// Same as [`AuditLog::open`], with an explicit configuration.
    ///
    /// # Errors
    ///
    /// Same as [`AuditLog::open`].
    pub fn open_with(dir: impl AsRef<Path>, config: AuditLogConfig) -> Result<Self, DbError> {
        let dir = dir.as_ref().to_path_buf();
        if !dir.is_dir() {
            return Err(DbError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "audit directory does not exist",
            )));
        }

        let existing = find_segments(&dir)?;
        let (current_number, current_path) = match existing.last() {
            Some((num, path)) => (*num, path.clone()),
            None => (1, segment_path(&dir, 1)),
        };

        let current = if current_path.exists() {
            let seg = AuditSegment::open(&current_path)?;
            seg.verify()?;
            seg
        } else {
            let seg = AuditSegment::new(None)?;
            seg.save(&current_path)?;
            seg
        };

        Ok(Self {
            dir,
            current,
            current_path,
            current_number,
            config,
        })
    }

    /// Returns the directory the log lives in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the identifier of the current segment.
    #[must_use]
    pub const fn current_segment_id(&self) -> SegmentId {
        self.current.id()
    }

    /// Returns the number of events in the current segment.
    #[must_use]
    pub fn current_len(&self) -> usize {
        self.current.len()
    }

    /// Returns the current segment's file name.
    #[must_use]
    pub fn current_path(&self) -> &Path {
        &self.current_path
    }

    /// Returns the events in the current segment.
    #[must_use]
    pub fn current_events(&self) -> &[AuditEvent] {
        self.current.events()
    }

    /// Returns the number of segments currently on disk.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Io`] if the directory cannot be read.
    pub fn segment_count(&self) -> Result<usize, DbError> {
        Ok(find_segments(&self.dir)?.len())
    }

    /// Appends an event, persisting the segment to disk before
    /// returning.
    ///
    /// If the current segment is at `max_events`, the log rotates
    /// first and the event lands in the new segment.
    ///
    /// # Errors
    ///
    /// Returns a [`DbError`] if the event cannot be built or the
    /// segment cannot be written. Callers must treat any error as a
    /// failed operation.
    pub fn append(
        &mut self,
        timestamp: Timestamp,
        spec: AuditEventSpec,
    ) -> Result<&AuditEvent, DbError> {
        if self.current.len() >= self.config.max_events {
            self.rotate()?;
        }

        self.current.append(timestamp, spec)?;
        // Persist immediately: no buffering.
        self.current.save(&self.current_path)?;
        Ok(self.current.events().last().expect("just appended"))
    }

    /// Rotates to a new segment.
    ///
    /// The current segment is kept as-is on disk. Its hash becomes
    /// the `prev_segment` of the new segment, which is created empty
    /// and written to disk before returning.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Io`] if the new segment cannot be written,
    /// or an error computing the current segment hash.
    pub fn rotate(&mut self) -> Result<(), DbError> {
        // Ensure the current segment is up to date on disk (append
        // already saves, but rotate can be called directly).
        self.current.save(&self.current_path)?;

        let prev_hash = self.current.segment_hash()?;
        let next_number = self.current_number + 1;
        let next_path = segment_path(&self.dir, next_number);

        let next = AuditSegment::new(Some(prev_hash))?;
        next.save(&next_path)?;

        self.current = next;
        self.current_path = next_path;
        self.current_number = next_number;
        Ok(())
    }

    /// Verifies every segment on disk and the links between them.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::RecordCrcMismatch`] if a segment's internal
    /// chain is broken, [`DbError::TrailerCrcMismatch`] if a segment
    /// hash does not match, or [`DbError::Io`] if the directory
    /// cannot be read.
    pub fn verify_all(&self) -> Result<(), DbError> {
        let segments = find_segments(&self.dir)?;
        let mut expected_prev: [u8; 32] = super::audit_event::GENESIS_HASH;

        for (_num, path) in &segments {
            let seg = AuditSegment::open(path)?;
            seg.verify()?;

            // The first segment must have prev = genesis; later ones
            // must match the previous segment's hash.
            if *seg.prev_segment() != expected_prev {
                return Err(DbError::RecordCrcMismatch);
            }

            expected_prev = seg.segment_hash()?;
        }

        Ok(())
    }
}

fn segment_path(dir: &Path, number: u32) -> PathBuf {
    dir.join(format!("audit-{number:05}.nqa"))
}

/// Returns the segments in `dir`, sorted by their numeric suffix.
///
/// Only files named `audit-NNNNN.nqa` are considered. Anything else
/// is ignored.
fn find_segments(dir: &Path) -> Result<Vec<(u32, PathBuf)>, DbError> {
    let mut found: Vec<(u32, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(number) = parse_segment_number(&path) {
            found.push((number, path));
        }
    }
    found.sort_by_key(|(n, _)| *n);
    Ok(found)
}

/// Parses `audit-NNNNN.nqa` into its numeric part.
///
/// Returns `None` for anything else.
fn parse_segment_number(path: &Path) -> Option<u32> {
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix("audit-")?;
    let digits = rest.strip_suffix(".nqa")?;
    if digits.len() != 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::audit_event::EventType;
    use tempfile::TempDir;

    fn ts(n: u64) -> Timestamp {
        Timestamp::from_secs(1_700_000_000 + n)
    }

    fn spec(kind: EventType) -> AuditEventSpec {
        AuditEventSpec::new(kind).with_actor("test")
    }

    fn init_dir() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let audit = dir.path().join("audit");
        fs::create_dir(&audit).unwrap();
        (dir, audit)
    }

    #[test]
    fn open_on_empty_dir_creates_first_segment() {
        let (_tmp, audit) = init_dir();
        let log = AuditLog::open(&audit).unwrap();
        assert_eq!(log.current_len(), 0);
        assert_eq!(log.segment_count().unwrap(), 1);
        assert!(audit.join("audit-00001.nqa").exists());
    }

    #[test]
    fn open_on_missing_dir_fails() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope");
        assert!(matches!(AuditLog::open(&missing), Err(DbError::Io(_))));
    }

    #[test]
    fn append_persists_and_is_readable() {
        let (_tmp, audit) = init_dir();
        let mut log = AuditLog::open(&audit).unwrap();
        log.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        log.append(ts(2), spec(EventType::KeyActivated)).unwrap();
        assert_eq!(log.current_len(), 2);

        // Reopen and check.
        let log2 = AuditLog::open(&audit).unwrap();
        assert_eq!(log2.current_len(), 2);
    }

    #[test]
    fn append_persists_across_reopen() {
        let (_tmp, audit) = init_dir();
        {
            let mut log = AuditLog::open(&audit).unwrap();
            log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        }
        {
            let mut log = AuditLog::open(&audit).unwrap();
            log.append(ts(2), spec(EventType::VaultUnlocked)).unwrap();
        }
        let log = AuditLog::open(&audit).unwrap();
        assert_eq!(log.current_len(), 2);
    }

    #[test]
    fn rotate_creates_a_second_segment() {
        let (_tmp, audit) = init_dir();
        let mut log = AuditLog::open(&audit).unwrap();
        log.append(ts(1), spec(EventType::KeyCreated)).unwrap();

        log.rotate().unwrap();
        assert_eq!(log.current_len(), 0);
        assert_eq!(log.segment_count().unwrap(), 2);
        assert!(audit.join("audit-00002.nqa").exists());

        // The new segment's prev_segment is the old hash.
        let log2 = AuditLog::open(&audit).unwrap();
        assert_eq!(log2.current_len(), 0);
    }

    #[test]
    fn auto_rotation_respects_max_events() {
        let (_tmp, audit) = init_dir();
        let config = AuditLogConfig { max_events: 3 };
        let mut log = AuditLog::open_with(&audit, config).unwrap();

        for i in 1..=3 {
            log.append(ts(i), spec(EventType::KeyUsed)).unwrap();
        }
        assert_eq!(log.current_len(), 3);
        assert_eq!(log.segment_count().unwrap(), 1);

        // The fourth append triggers rotation.
        log.append(ts(4), spec(EventType::KeyUsed)).unwrap();
        assert_eq!(log.current_len(), 1);
        assert_eq!(log.segment_count().unwrap(), 2);
    }

    #[test]
    fn verify_all_accepts_a_fresh_chain() {
        let (_tmp, audit) = init_dir();
        let mut log = AuditLog::open(&audit).unwrap();
        for i in 1..=3 {
            log.append(ts(i), spec(EventType::KeyCreated)).unwrap();
        }
        log.rotate().unwrap();
        for i in 4..=5 {
            log.append(ts(i), spec(EventType::KeyUsed)).unwrap();
        }
        log.verify_all().unwrap();
    }

    #[test]
    fn verify_all_detects_a_break() {
        let (_tmp, audit) = init_dir();
        let mut log = AuditLog::open(&audit).unwrap();
        log.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        log.rotate().unwrap();
        log.append(ts(2), spec(EventType::KeyUsed)).unwrap();

        // Corrupt the second segment: flip a byte in the middle.
        let path = audit.join("audit-00002.nqa");
        let mut bytes = fs::read(&path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        assert!(log.verify_all().is_err());
    }

    #[test]
    fn segment_number_parser_accepts_correct_names() {
        assert_eq!(parse_segment_number(Path::new("audit-00001.nqa")), Some(1));
        assert_eq!(
            parse_segment_number(Path::new("audit-12345.nqa")),
            Some(12345)
        );
    }

    #[test]
    fn segment_number_parser_rejects_other_names() {
        assert_eq!(parse_segment_number(Path::new("audit.nqa")), None);
        assert_eq!(parse_segment_number(Path::new("audit-abcde.nqa")), None);
        assert_eq!(parse_segment_number(Path::new("audit-1.nqa")), None);
        assert_eq!(parse_segment_number(Path::new("other-00001.nqa")), None);
        assert_eq!(parse_segment_number(Path::new("audit-00001.txt")), None);
    }

    #[test]
    fn ignores_unrelated_files() {
        let (_tmp, audit) = init_dir();
        fs::write(audit.join("notes.txt"), b"hi").unwrap();
        fs::write(audit.join("audit-abc.nqa"), b"junk").unwrap();

        let log = AuditLog::open(&audit).unwrap();
        assert_eq!(log.segment_count().unwrap(), 1);
    }
}

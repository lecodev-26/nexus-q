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
//! operate" rule from `docs/SECURITY_MODEL.md` §7.7.
//!
//! ## Performance note
//!
//! Because the F-04 format carries the segment hash in a trailer,
//! appending means rewriting the whole segment. Segments are
//! bounded, so this is acceptable; a future version may adopt an
//! appendable layout with per-event CRCs and a separate index.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::Timestamp;

use super::atomic::{replace_file, sync_parent_dir};
use super::audit_event::{AuditEvent, AuditEventSpec, EventType, HASH_LEN};
use super::audit_segment::{AuditSegment, KEY_EPOCH_ID_LEN, SegmentId};
use super::db::DbError;

/// Default maximum number of events per segment.
pub const DEFAULT_MAX_EVENTS: usize = 1000;
const LEGACY_ANCHOR_MAGIC: &[u8] = b"NQA3";
const ANCHOR_MAGIC: &[u8] = b"NQA4";
const LEGACY_EPOCH_ID: [u8; KEY_EPOCH_ID_LEN] = [0u8; KEY_EPOCH_ID_LEN];
const ANCHOR_FILE: &str = "audit.anchor";

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
pub struct AuditLog {
    dir: PathBuf,
    current: AuditSegment,
    current_path: PathBuf,
    current_number: u32,
    config: AuditLogConfig,
    keyring: BTreeMap<[u8; KEY_EPOCH_ID_LEN], Zeroizing<[u8; 32]>>,
    current_epoch: [u8; KEY_EPOCH_ID_LEN],
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
    /// written, or a parse error if the segment being opened is
    /// malformed.
    pub fn open(dir: impl AsRef<Path>, auth_key: &[u8; 32]) -> Result<Self, DbError> {
        Self::open_with(dir, AuditLogConfig::default(), auth_key)
    }

    /// Same as [`AuditLog::open`], with an explicit configuration.
    ///
    /// # Errors
    ///
    /// Same as [`AuditLog::open`].
    pub fn open_with(
        dir: impl AsRef<Path>,
        config: AuditLogConfig,
        auth_key: &[u8; 32],
    ) -> Result<Self, DbError> {
        let mut keys = [(LEGACY_EPOCH_ID, *auth_key)];
        let result = Self::open_with_keyring(dir, config, &keys, &LEGACY_EPOCH_ID);
        keys[0].1.zeroize();
        result
    }

    /// Opens a log with all retained authentication epochs and the epoch
    /// that must authenticate newly appended events.
    pub fn open_with_keyring(
        dir: impl AsRef<Path>,
        config: AuditLogConfig,
        keys: &[([u8; KEY_EPOCH_ID_LEN], [u8; 32])],
        current_epoch: &[u8; KEY_EPOCH_ID_LEN],
    ) -> Result<Self, DbError> {
        let dir = dir.as_ref().to_path_buf();
        if !dir.is_dir() {
            return Err(DbError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "audit directory does not exist",
            )));
        }
        let mut keyring = BTreeMap::new();
        for (id, key) in keys {
            if keyring.insert(*id, Zeroizing::new(*key)).is_some() {
                return Err(DbError::AuditAnchorMismatch);
            }
        }
        if !keyring.contains_key(current_epoch) {
            return Err(DbError::AuditAnchorMismatch);
        }
        let existing = find_segments(&dir)?;
        let (current_number, current_path) = match existing.last() {
            Some((num, path)) => (*num, path.clone()),
            None => (1, segment_path(&dir, 1)),
        };
        let current = if current_path.exists() {
            let mut seg = AuditSegment::open(&current_path)?;
            let key = keyring
                .get(seg.key_epoch_id())
                .ok_or(DbError::AuditAnchorMismatch)?;
            seg.set_auth_key(key);
            seg.verify()?;
            seg
        } else {
            let key = keyring
                .get(current_epoch)
                .ok_or(DbError::AuditAnchorMismatch)?;
            let seg = AuditSegment::new_with_key_epoch(None, key, current_epoch)?;
            seg.save(&current_path)?;
            seg
        };
        let mut log = Self {
            dir,
            current,
            current_path,
            current_number,
            config,
            keyring,
            current_epoch: *current_epoch,
        };
        if !log.anchor_path().exists() {
            if existing.is_empty() {
                log.persist_anchor()?;
            } else {
                return Err(DbError::AuditAnchorMismatch);
            }
        }
        log.verify_all()?;
        // A rotation is represented by a new segment. If the vault has
        // durably committed a newer current epoch but the process stopped
        // before creating that segment, finish the transition now.
        if log.current.key_epoch_id() != current_epoch {
            log.rotate_to_epoch(*current_epoch)?;
        } else {
            // Also completes an interrupted rotation where the new empty
            // segment reached disk but its anchor replacement did not.
            log.persist_anchor()?;
        }
        Ok(log)
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

    /// Returns the hash of the latest authenticated event, if any.
    #[must_use]
    pub fn head_event_hash(&self) -> Option<&[u8]> {
        self.current
            .events()
            .last()
            .map(|event| event.hash.as_slice())
    }

    /// Returns whether an authenticated event hash exists anywhere in the log.
    pub fn contains_event_hash(&self, anchor: &[u8]) -> bool {
        if anchor.len() != HASH_LEN {
            return false;
        }
        let Ok(segments) = find_segments(&self.dir) else {
            return false;
        };
        let mut expected_prev = super::audit_event::GENESIS_HASH;
        let mut last_number = None;
        let mut found = false;

        // Re-read and validate the complete chain in one pass. Individual
        // segment authentication is insufficient: a valid segment replayed
        // into a different position must not satisfy an anchor lookup.
        for (number, path) in segments {
            last_number = Some(number);
            let Ok(mut segment) = AuditSegment::open(&path) else {
                return false;
            };
            let Some(key) = self.keyring.get(segment.key_epoch_id()) else {
                return false;
            };
            segment.set_auth_key(key);
            if segment.verify().is_err() || *segment.prev_segment() != expected_prev {
                return false;
            }

            found |= segment
                .events()
                .iter()
                .any(|event| event.hash.as_slice() == anchor);
            let Ok(segment_hash) = segment.segment_hash() else {
                return false;
            };
            expected_prev = segment_hash;
        }

        let Ok(current_hash) = self.current.segment_hash() else {
            return false;
        };

        // The chain must still terminate at the exact authenticated tail
        // held by this AuditLog instance, not merely at any valid old chain.
        found && last_number == Some(self.current_number) && expected_prev == current_hash
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
        // Persist immediately: no buffering. The authenticated tail
        // commitment is updated only after the segment is durable.
        self.current.save(&self.current_path)?;
        self.persist_anchor()?;
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

        let key = self
            .keyring
            .get(&self.current_epoch)
            .ok_or(DbError::AuditAnchorMismatch)?;
        let next = AuditSegment::new_with_key_epoch(Some(prev_hash), key, &self.current_epoch)?;
        next.save(&next_path)?;

        self.current = next;
        self.current_path = next_path;
        self.current_number = next_number;
        self.persist_anchor()?;
        Ok(())
    }

    /// Adds a retained epoch to this open log. Callers must durably persist
    /// the corresponding key in the encrypted vault before invoking this.
    pub fn add_key_epoch(
        &mut self,
        epoch: [u8; KEY_EPOCH_ID_LEN],
        key: &[u8; 32],
    ) -> Result<(), DbError> {
        if epoch == LEGACY_EPOCH_ID || self.keyring.contains_key(&epoch) {
            return Err(DbError::AuditAnchorMismatch);
        }
        self.keyring.insert(epoch, Zeroizing::new(*key));
        Ok(())
    }

    /// Switches future events to a previously persisted key epoch.
    /// The old segments remain untouched and verifiable with their retained keys.
    pub fn rotate_to_epoch(&mut self, epoch: [u8; KEY_EPOCH_ID_LEN]) -> Result<(), DbError> {
        if !self.keyring.contains_key(&epoch) {
            return Err(DbError::AuditAnchorMismatch);
        }
        if self.current.key_epoch_id() == &epoch {
            self.current_epoch = epoch;
            return Ok(());
        }
        self.current.save(&self.current_path)?;
        let prev_hash = self.current.segment_hash()?;
        let next_number = self
            .current_number
            .checked_add(1)
            .ok_or(DbError::LengthLimitExceeded)?;
        let next_path = segment_path(&self.dir, next_number);
        let key = self
            .keyring
            .get(&epoch)
            .ok_or(DbError::AuditAnchorMismatch)?;
        let mut next = AuditSegment::new_with_key_epoch(Some(prev_hash), key, &epoch)?;
        let timestamp = Timestamp::now()
            .map_err(|error| DbError::Io(std::io::Error::other(error.to_string())))?;
        next.append(
            timestamp,
            AuditEventSpec::new(EventType::KeyRotated)
                .with_actor("vault")
                .with_subject(hex::encode(epoch)),
        )?;
        // Persist the transition event with the new segment so recovery
        // never exposes a committed epoch switch without its audit record.
        next.save(&next_path)?;
        self.current = next;
        self.current_path = next_path;
        self.current_number = next_number;
        self.current_epoch = epoch;
        self.persist_anchor()?;
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
            let mut seg = AuditSegment::open(path)?;
            let key = self
                .keyring
                .get(seg.key_epoch_id())
                .ok_or(DbError::AuditAnchorMismatch)?;
            seg.set_auth_key(key);
            seg.verify()?;

            // The first segment must have prev = genesis; later ones
            // must match the previous segment's hash.
            if *seg.prev_segment() != expected_prev {
                return Err(DbError::RecordCrcMismatch);
            }

            expected_prev = seg.segment_hash()?;
        }

        self.verify_anchor()?;
        Ok(())
    }

    fn anchor_path(&self) -> PathBuf {
        self.dir.join(ANCHOR_FILE)
    }

    fn persist_anchor(&self) -> Result<(), DbError> {
        let segment_hash = self.current.segment_hash()?;
        let key = self
            .keyring
            .get(&self.current_epoch)
            .ok_or(DbError::AuditAnchorMismatch)?;
        let mac = authenticate_anchor(
            key,
            &self.current_number.to_be_bytes(),
            &self.current_epoch,
            &segment_hash,
        );
        let mut bytes =
            Vec::with_capacity(ANCHOR_MAGIC.len() + 4 + KEY_EPOCH_ID_LEN + HASH_LEN + HASH_LEN);
        bytes.extend_from_slice(ANCHOR_MAGIC);
        bytes.extend_from_slice(&self.current_number.to_be_bytes());
        bytes.extend_from_slice(&self.current_epoch);
        bytes.extend_from_slice(&segment_hash);
        bytes.extend_from_slice(&mac);

        // Reserve the temporary file atomically; never overwrite a
        // pre-existing attacker/concurrent-writer path.
        let (tmp, mut file) = create_unique_temp_file(&self.anchor_path())?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&tmp, &self.anchor_path())?;
        sync_parent_dir(&self.anchor_path())?;
        Ok(())
    }

    fn verify_anchor(&self) -> Result<(), DbError> {
        let bytes = fs::read(self.anchor_path()).map_err(|_| DbError::AuditAnchorMismatch)?;
        let legacy_len = LEGACY_ANCHOR_MAGIC.len() + 4 + HASH_LEN + HASH_LEN;
        let current_len = ANCHOR_MAGIC.len() + 4 + KEY_EPOCH_ID_LEN + HASH_LEN + HASH_LEN;
        let (magic_len, epoch, hash_start, mac_start, key, legacy) =
            if bytes.len() == current_len && &bytes[..4] == ANCHOR_MAGIC {
                let mut epoch = [0u8; KEY_EPOCH_ID_LEN];
                epoch.copy_from_slice(&bytes[4 + 4..4 + 4 + KEY_EPOCH_ID_LEN]);
                let key = self
                    .keyring
                    .get(&epoch)
                    .ok_or(DbError::AuditAnchorMismatch)?;
                (
                    4usize,
                    epoch,
                    8 + KEY_EPOCH_ID_LEN,
                    8 + KEY_EPOCH_ID_LEN + HASH_LEN,
                    key,
                    false,
                )
            } else if bytes.len() == legacy_len && &bytes[..4] == LEGACY_ANCHOR_MAGIC {
                let key = self
                    .keyring
                    .get(&LEGACY_EPOCH_ID)
                    .ok_or(DbError::AuditAnchorMismatch)?;
                (4usize, LEGACY_EPOCH_ID, 8, 8 + HASH_LEN, key, true)
            } else {
                return Err(DbError::AuditAnchorMismatch);
            };
        let number =
            u32::from_be_bytes(bytes[magic_len..magic_len + 4].try_into().expect("4 bytes"));
        let mut segment_hash = [0u8; HASH_LEN];
        segment_hash.copy_from_slice(&bytes[hash_start..hash_start + HASH_LEN]);
        let mut stored_mac = [0u8; HASH_LEN];
        stored_mac.copy_from_slice(&bytes[mac_start..]);
        let expected_mac = if legacy {
            authenticate_legacy_anchor(key, &number.to_be_bytes(), &segment_hash)
        } else {
            authenticate_anchor(key, &number.to_be_bytes(), &epoch, &segment_hash)
        };
        let current_hash = self.current.segment_hash()?;
        let current_anchor = number == self.current_number
            && epoch == *self.current.key_epoch_id()
            && bool::from(segment_hash.ct_eq(&current_hash));
        let interrupted_epoch_switch = if number.checked_add(1) == Some(self.current_number)
            && *self.current.prev_segment() == segment_hash
        {
            let previous_path = segment_path(&self.dir, number);
            if let Ok(mut previous) = AuditSegment::open(previous_path) {
                if previous.key_epoch_id() == &epoch {
                    if let Some(previous_key) = self.keyring.get(&epoch) {
                        previous.set_auth_key(previous_key);
                        previous.verify().is_ok()
                            && previous
                                .segment_hash()
                                .is_ok_and(|hash| hash == segment_hash)
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        if (!current_anchor && !interrupted_epoch_switch)
            || !bool::from(stored_mac.ct_eq(&expected_mac))
        {
            return Err(DbError::AuditAnchorMismatch);
        }
        Ok(())
    }
}

fn create_unique_temp_file(path: &Path) -> Result<(PathBuf, fs::File), DbError> {
    for _ in 0..16 {
        let mut suffix = [0u8; 16];
        getrandom::fill(&mut suffix)
            .map_err(|e| DbError::Io(std::io::Error::other(e.to_string())))?;
        let name = format!(
            "{}.tmp-{}",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("audit"),
            hex::encode(suffix)
        );
        let tmp = path.with_file_name(name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(DbError::Io(err)),
        }
    }
    Err(DbError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate unique audit anchor temp file",
    )))
}

fn authenticate_legacy_anchor(
    key: &[u8; HASH_LEN],
    number: &[u8; 4],
    segment_hash: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut data =
        Vec::with_capacity(LEGACY_ANCHOR_MAGIC.len() + number.len() + segment_hash.len());
    data.extend_from_slice(LEGACY_ANCHOR_MAGIC);
    data.extend_from_slice(number);
    data.extend_from_slice(segment_hash);
    authenticate_anchor_mac(key, &data)
}

fn authenticate_anchor(
    key: &[u8; HASH_LEN],
    number: &[u8; 4],
    epoch: &[u8; KEY_EPOCH_ID_LEN],
    segment_hash: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut data =
        Vec::with_capacity(ANCHOR_MAGIC.len() + number.len() + epoch.len() + segment_hash.len());
    data.extend_from_slice(ANCHOR_MAGIC);
    data.extend_from_slice(number);
    data.extend_from_slice(epoch);
    data.extend_from_slice(segment_hash);
    authenticate_anchor_mac(key, &data)
}

fn authenticate_anchor_mac(key: &[u8; HASH_LEN], data: &[u8]) -> [u8; HASH_LEN] {
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

    const TEST_KEY: [u8; 32] = [0x42; 32];
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
        let log = AuditLog::open(&audit, &TEST_KEY).unwrap();
        assert_eq!(log.current_len(), 0);
        assert_eq!(log.segment_count().unwrap(), 1);
        assert!(audit.join("audit-00001.nqa").exists());
    }

    #[test]
    fn open_on_missing_dir_fails() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope");
        assert!(matches!(
            AuditLog::open(&missing, &TEST_KEY),
            Err(DbError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn audit_segment_and_anchor_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (_tmp, audit) = init_dir();
        let _log = AuditLog::open(&audit, &TEST_KEY).unwrap();

        for path in [audit.join("audit-00001.nqa"), audit.join(ANCHOR_FILE)] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn opening_with_a_different_authentication_key_fails_closed() {
        let (_tmp, audit) = init_dir();
        {
            let mut log = AuditLog::open(&audit, &TEST_KEY).unwrap();
            log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
            log.rotate().unwrap();
            log.append(ts(2), spec(EventType::VaultUnlocked)).unwrap();
            log.verify_all().unwrap();
        }

        // A replacement key must not silently authenticate old segments or
        // the tail commitment. Key rotation needs an explicit epoch protocol.
        let replacement_key = [0x24; 32];
        assert!(AuditLog::open(&audit, &replacement_key).is_err());
        assert!(AuditLog::open(&audit, &TEST_KEY).is_ok());
    }

    #[test]
    fn key_rotation_preserves_historical_segments_and_reopens() {
        let (_tmp, audit) = init_dir();
        let epoch = [0x19; KEY_EPOCH_ID_LEN];
        let replacement = [0x73; 32];
        let keys = [(LEGACY_EPOCH_ID, TEST_KEY), (epoch, replacement)];
        let mut log = AuditLog::open_with_keyring(
            &audit,
            AuditLogConfig::default(),
            &[(LEGACY_EPOCH_ID, TEST_KEY)],
            &LEGACY_EPOCH_ID,
        )
        .unwrap();
        log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        let old_hash = log.head_event_hash().unwrap().to_vec();
        log.add_key_epoch(epoch, &replacement).unwrap();
        log.rotate_to_epoch(epoch).unwrap();
        log.append(ts(2), spec(EventType::VaultUnlocked)).unwrap();
        let new_hash = log.head_event_hash().unwrap().to_vec();
        log.verify_all().unwrap();
        drop(log);

        let reopened =
            AuditLog::open_with_keyring(&audit, AuditLogConfig::default(), &keys, &epoch).unwrap();
        assert!(reopened.contains_event_hash(&old_hash));
        assert!(reopened.contains_event_hash(&new_hash));
        assert_eq!(reopened.segment_count().unwrap(), 2);
    }

    #[test]
    fn missing_historical_epoch_fails_closed() {
        let (_tmp, audit) = init_dir();
        let epoch = [0x39; KEY_EPOCH_ID_LEN];
        let replacement = [0x64; 32];
        let keys = [(LEGACY_EPOCH_ID, TEST_KEY), (epoch, replacement)];
        let mut log = AuditLog::open_with_keyring(
            &audit,
            AuditLogConfig::default(),
            &[(LEGACY_EPOCH_ID, TEST_KEY)],
            &LEGACY_EPOCH_ID,
        )
        .unwrap();
        log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        log.add_key_epoch(epoch, &replacement).unwrap();
        log.rotate_to_epoch(epoch).unwrap();
        drop(log);
        assert!(
            AuditLog::open_with_keyring(
                &audit,
                AuditLogConfig::default(),
                &[(epoch, replacement)],
                &epoch
            )
            .is_err()
        );
    }

    #[test]
    fn interrupted_epoch_rotation_repairs_the_tail_anchor() {
        let (_tmp, audit) = init_dir();
        let epoch = [0x29; KEY_EPOCH_ID_LEN];
        let replacement = [0x64; 32];
        let keys = [(LEGACY_EPOCH_ID, TEST_KEY), (epoch, replacement)];
        let mut log = AuditLog::open_with_keyring(
            &audit,
            AuditLogConfig::default(),
            &[(LEGACY_EPOCH_ID, TEST_KEY)],
            &LEGACY_EPOCH_ID,
        )
        .unwrap();
        log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        let old_anchor = fs::read(audit.join(ANCHOR_FILE)).unwrap();
        log.add_key_epoch(epoch, &replacement).unwrap();
        log.rotate_to_epoch(epoch).unwrap();
        // Model a crash after the new segment and transition event are durable but
        // before the NQA4 tail anchor replacement reaches disk.
        fs::write(audit.join(ANCHOR_FILE), old_anchor).unwrap();
        drop(log);

        let recovered =
            AuditLog::open_with_keyring(&audit, AuditLogConfig::default(), &keys, &epoch).unwrap();
        recovered.verify_all().unwrap();
        assert_eq!(recovered.segment_count().unwrap(), 2);
    }

    #[test]
    fn append_persists_and_is_readable() {
        let (_tmp, audit) = init_dir();
        let mut log = AuditLog::open(&audit, &TEST_KEY).unwrap();
        log.append(ts(1), spec(EventType::KeyCreated)).unwrap();
        log.append(ts(2), spec(EventType::KeyActivated)).unwrap();
        assert_eq!(log.current_len(), 2);

        // Reopen and check.
        let log2 = AuditLog::open(&audit, &TEST_KEY).unwrap();
        assert_eq!(log2.current_len(), 2);
    }

    #[test]
    fn contains_event_hash_rejects_a_tampered_segment() {
        let dir = TempDir::new().unwrap();
        let key = [0x42; 32];
        let mut log = AuditLog::open(dir.path(), &key).unwrap();
        log.append(
            ts(1),
            AuditEventSpec::new(EventType::KeyCreated)
                .with_actor("alice")
                .with_subject("key-1"),
        )
        .unwrap();
        let anchor = log.head_event_hash().unwrap().to_vec();
        let path = log.current_path().to_path_buf();
        let mut bytes = fs::read(&path).unwrap();
        let actor_offset = bytes
            .windows(b"alice".len())
            .position(|window| window == b"alice")
            .unwrap();
        bytes[actor_offset..actor_offset + b"alice".len()].copy_from_slice(b"xxxxx");
        fs::write(path, bytes).unwrap();

        assert!(!log.contains_event_hash(&anchor));
    }

    #[test]
    fn contains_event_hash_rejects_a_valid_segment_with_a_broken_link() {
        let (_tmp, audit) = init_dir();
        let mut log =
            AuditLog::open_with(&audit, AuditLogConfig { max_events: 1 }, &TEST_KEY).unwrap();
        log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        let original_anchor = log.head_event_hash().unwrap().to_vec();
        log.append(ts(2), spec(EventType::VaultUnlocked)).unwrap();

        // Replace segment 1 with a separately authenticated segment. Its
        // own contents and MAC are valid, but segment 2 still links to the
        // original segment 1 hash, so the complete chain is invalid.
        let mut replacement = AuditSegment::new_with_key(None, &TEST_KEY).unwrap();
        replacement
            .append(ts(3), spec(EventType::KeyCreated))
            .unwrap();
        let replacement_anchor = replacement.events()[0].hash.clone();
        replacement.save(audit.join("audit-00001.nqa")).unwrap();

        assert_ne!(replacement_anchor, original_anchor);
        assert!(!log.contains_event_hash(&replacement_anchor));
    }

    #[test]
    fn contains_event_hash_rejects_a_replayed_valid_chain() {
        let (_tmp, audit) = init_dir();
        let config = AuditLogConfig { max_events: 1 };
        let mut log = AuditLog::open_with(&audit, config, &TEST_KEY).unwrap();
        log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        log.append(ts(2), spec(EventType::VaultUnlocked)).unwrap();

        // Build a different, fully authenticated chain with the same key
        // and segment numbers, then replay it over the on-disk log.
        let (_stale_tmp, stale_audit) = init_dir();
        let mut stale = AuditLog::open_with(&stale_audit, config, &TEST_KEY).unwrap();
        stale.append(ts(10), spec(EventType::KeyCreated)).unwrap();
        let stale_anchor = stale.head_event_hash().unwrap().to_vec();
        stale.append(ts(11), spec(EventType::KeyUsed)).unwrap();

        for number in 1..=2 {
            fs::copy(
                stale_audit.join(format!("audit-{number:05}.nqa")),
                audit.join(format!("audit-{number:05}.nqa")),
            )
            .unwrap();
        }

        assert!(!log.contains_event_hash(&stale_anchor));
    }

    #[test]
    fn tail_truncation_is_rejected_by_authenticated_anchor() {
        let (_tmp, audit) = init_dir();
        {
            let mut log = AuditLog::open(&audit, &TEST_KEY).unwrap();
            log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
            log.append(ts(2), spec(EventType::VaultUnlocked)).unwrap();
        }
        let path = audit.join("audit-00001.nqa");
        let mut bytes = fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 8);
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            AuditLog::open(&audit, &TEST_KEY),
            Err(DbError::RecordCrcMismatch)
                | Err(DbError::TrailerCrcMismatch)
                | Err(DbError::MalformedRecord)
        ));
    }

    #[test]
    fn removing_tail_segment_is_rejected_by_authenticated_anchor() {
        let (_tmp, audit) = init_dir();
        let config = AuditLogConfig { max_events: 1 };
        {
            let mut log = AuditLog::open_with(&audit, config, &TEST_KEY).unwrap();
            log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
            log.append(ts(2), spec(EventType::VaultUnlocked)).unwrap();
        }
        fs::remove_file(audit.join("audit-00002.nqa")).unwrap();
        assert!(matches!(
            AuditLog::open_with(&audit, config, &TEST_KEY),
            Err(DbError::AuditAnchorMismatch)
        ));
    }

    #[test]
    fn removing_authenticated_anchor_fails_closed() {
        let (_tmp, audit) = init_dir();
        let mut log = AuditLog::open(&audit, &TEST_KEY).unwrap();
        log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        fs::remove_file(audit.join(ANCHOR_FILE)).unwrap();
        assert!(matches!(
            AuditLog::open(&audit, &TEST_KEY),
            Err(DbError::AuditAnchorMismatch)
        ));
    }

    #[test]
    fn append_persists_across_reopen() {
        let (_tmp, audit) = init_dir();
        {
            let mut log = AuditLog::open(&audit, &TEST_KEY).unwrap();
            log.append(ts(1), spec(EventType::VaultCreated)).unwrap();
        }
        {
            let mut log = AuditLog::open(&audit, &TEST_KEY).unwrap();
            log.append(ts(2), spec(EventType::VaultUnlocked)).unwrap();
        }
        let log = AuditLog::open(&audit, &TEST_KEY).unwrap();
        assert_eq!(log.current_len(), 2);
    }

    #[test]
    fn rotate_creates_a_second_segment() {
        let (_tmp, audit) = init_dir();
        let mut log = AuditLog::open(&audit, &TEST_KEY).unwrap();
        log.append(ts(1), spec(EventType::KeyCreated)).unwrap();

        log.rotate().unwrap();
        assert_eq!(log.current_len(), 0);
        assert_eq!(log.segment_count().unwrap(), 2);
        assert!(audit.join("audit-00002.nqa").exists());

        // The new segment's prev_segment is the old hash.
        let log2 = AuditLog::open(&audit, &TEST_KEY).unwrap();
        assert_eq!(log2.current_len(), 0);
    }

    #[test]
    fn auto_rotation_respects_max_events() {
        let (_tmp, audit) = init_dir();
        let config = AuditLogConfig { max_events: 3 };
        let mut log = AuditLog::open_with(&audit, config, &TEST_KEY).unwrap();

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
        let mut log = AuditLog::open(&audit, &TEST_KEY).unwrap();
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
        let mut log = AuditLog::open(&audit, &TEST_KEY).unwrap();
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

        let log = AuditLog::open(&audit, &TEST_KEY).unwrap();
        assert_eq!(log.segment_count().unwrap(), 1);
    }
}

//! Tenant isolation and high-availability primitives for NexusQ CA/OCSP services.
//!
//! This crate deliberately does not invent its own leader-election consensus protocol or network
//! security. Deployments provide authenticated `ReplicaPeer` implementations and a lease from a
//! consensus-backed control plane. The journal enforces tenant scoping, durable prepare/commit
//! records, hash-chain integrity, and leader fencing; it is not by itself a complete cluster.

use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Seek, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_TENANT_ID_BYTES: usize = 63;
const DEFAULT_RPO: Duration = Duration::from_secs(60 * 60);
const DEFAULT_RTO: Duration = Duration::from_secs(4 * 60 * 60);

/// Opaque tenant namespace. Only lowercase DNS-label-like IDs are accepted for safe path use.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(String);

impl TenantId {
    /// Validate and create a tenant ID.
    pub fn new(value: impl Into<String>) -> Result<Self, HaError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_TENANT_ID_BYTES
            || !value.is_ascii()
            || value.starts_with('-')
            || value.ends_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(HaError::InvalidTenantId);
        }
        Ok(Self(value))
    }
    /// Stable tenant namespace string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Per-tenant service metadata. Key material is intentionally not stored in this catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TenantDescriptor {
    /// Tenant namespace.
    pub id: TenantId,
    /// SHA-256 fingerprint of the configured CA certificate DER.
    pub ca_certificate_sha256: [u8; 32],
    /// Maximum requests per minute for this tenant.
    pub requests_per_minute: u32,
    /// Whether this tenant is enabled for new issuance.
    pub issuance_enabled: bool,
}

/// Thread-safe catalog that keeps tenant identities and policies in separate namespaces.
#[derive(Default)]
pub struct TenantCatalog {
    tenants: RwLock<BTreeMap<TenantId, TenantDescriptor>>,
    path: Option<PathBuf>,
}
impl TenantCatalog {
    /// Create an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a durable tenant catalog, validating every persisted identifier and policy.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, HaError> {
        let path = path.as_ref().to_path_buf();
        let mut tenants = BTreeMap::new();
        if path.exists() {
            let bytes = fs::read(&path).map_err(|_| HaError::StorageUnavailable)?;
            let entries: Vec<TenantDescriptor> =
                serde_json::from_slice(&bytes).map_err(|_| HaError::CatalogCorrupt)?;
            for descriptor in entries {
                if TenantId::new(descriptor.id.as_str())? != descriptor.id
                    || descriptor.requests_per_minute == 0
                    || tenants.insert(descriptor.id.clone(), descriptor).is_some()
                {
                    return Err(HaError::CatalogCorrupt);
                }
            }
        }
        let catalog = Self {
            tenants: RwLock::new(tenants),
            path: Some(path),
        };
        catalog.persist()?;
        Ok(catalog)
    }

    fn persist(&self) -> Result<(), HaError> {
        if let Some(path) = &self.path {
            let tenants = self.tenants.read().map_err(|_| HaError::StateUnavailable)?;
            let entries = tenants.values().cloned().collect::<Vec<_>>();
            let bytes = serde_json::to_vec(&entries).map_err(|_| HaError::Encoding)?;
            atomic_write(path, &bytes)?;
        }
        Ok(())
    }

    /// Register a tenant; duplicate IDs are rejected rather than overwritten.
    pub fn register(&self, descriptor: TenantDescriptor) -> Result<(), HaError> {
        if descriptor.requests_per_minute == 0 {
            return Err(HaError::InvalidTenantPolicy);
        }
        let mut tenants = self
            .tenants
            .write()
            .map_err(|_| HaError::StateUnavailable)?;
        if tenants.contains_key(&descriptor.id) {
            return Err(HaError::TenantAlreadyExists);
        }
        let id = descriptor.id.clone();
        tenants.insert(id.clone(), descriptor);
        if let Some(path) = &self.path {
            let bytes = serde_json::to_vec(&tenants.values().cloned().collect::<Vec<_>>())
                .map_err(|_| HaError::Encoding)?;
            if atomic_write(path, &bytes).is_err() {
                tenants.remove(&id);
                return Err(HaError::StorageUnavailable);
            }
        }
        Ok(())
    }
    /// Retrieve a descriptor without exposing mutable internal state.
    pub fn get(&self, tenant: &TenantId) -> Result<TenantDescriptor, HaError> {
        self.tenants
            .read()
            .map_err(|_| HaError::StateUnavailable)?
            .get(tenant)
            .cloned()
            .ok_or(HaError::TenantNotFound)
    }
    /// List tenant IDs in stable order.
    pub fn tenant_ids(&self) -> Result<Vec<TenantId>, HaError> {
        Ok(self
            .tenants
            .read()
            .map_err(|_| HaError::StateUnavailable)?
            .keys()
            .cloned()
            .collect())
    }
    /// Enable or disable issuance for one tenant only.
    pub fn set_issuance(&self, tenant: &TenantId, enabled: bool) -> Result<(), HaError> {
        let mut tenants = self
            .tenants
            .write()
            .map_err(|_| HaError::StateUnavailable)?;
        let descriptor = tenants.get_mut(tenant).ok_or(HaError::TenantNotFound)?;
        let previous = descriptor.issuance_enabled;
        descriptor.issuance_enabled = enabled;
        if let Some(path) = &self.path {
            let bytes = serde_json::to_vec(&tenants.values().cloned().collect::<Vec<_>>())
                .map_err(|_| HaError::Encoding)?;
            if atomic_write(path, &bytes).is_err() {
                tenants
                    .get_mut(tenant)
                    .expect("tenant remains registered")
                    .issuance_enabled = previous;
                return Err(HaError::StorageUnavailable);
            }
        }
        Ok(())
    }
}

/// A single durable CA/OCSP state mutation, scoped to exactly one tenant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JournalRecord {
    /// Tenant namespace.
    pub tenant: TenantId,
    /// Monotonic journal sequence (aborted sequence numbers are not reused).
    pub sequence: u64,
    /// Consensus term/fencing epoch under which the leader proposed this mutation.
    pub term: u64,
    /// Domain such as `certificate.issued`, `certificate.revoked`, or `crl.published`.
    pub kind: String,
    /// Opaque application payload. Callers must not include passwords or private keys.
    pub payload: Vec<u8>,
    /// Hash of the last committed record for this tenant.
    pub previous_hash: [u8; 32],
    /// SHA-256 integrity hash over the record's canonical field sequence.
    pub hash: [u8; 32],
    /// UTC Unix time in seconds.
    pub created_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
enum JournalFrame {
    Prepared { record: JournalRecord },
    Committed { sequence: u64, hash: [u8; 32] },
    Aborted { sequence: u64, hash: [u8; 32] },
    SequenceAdvance { next_sequence: u64 },
    FencingAdvance { highest_term: u64 },
}

struct JournalState {
    file: File,
    committed: Vec<JournalRecord>,
    pending: HashMap<u64, JournalRecord>,
    next_sequence: u64,
    last_hash: [u8; 32],
    highest_term: u64,
}

struct RecoveredFrames {
    committed: Vec<JournalRecord>,
    pending: HashMap<u64, JournalRecord>,
    next_sequence: u64,
    last_hash: [u8; 32],
    highest_term: u64,
}

/// Integrity-checked, tenant-scoped snapshot for disaster recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JournalSnapshot {
    /// Snapshot format version.
    pub version: u32,
    /// Tenant namespace covered by the snapshot.
    pub tenant: TenantId,
    /// Next sequence number to allocate, preserving aborted sequence gaps.
    pub next_sequence: u64,
    /// Highest fencing term observed, including aborted prepares.
    pub highest_term: u64,
    /// Committed records in order.
    pub records: Vec<JournalRecord>,
    /// SHA-256 checksum of the canonical snapshot body.
    pub checksum: [u8; 32],
}

#[derive(Serialize)]
struct SnapshotBody<'a> {
    version: u32,
    tenant: &'a TenantId,
    next_sequence: u64,
    highest_term: u64,
    records: &'a [JournalRecord],
}

/// Per-tenant append-only journal. Each frame is fsynced before success is returned.
pub struct DurableTenantJournal {
    tenant: TenantId,
    path: PathBuf,
    state: Mutex<JournalState>,
}

impl DurableTenantJournal {
    /// Open/create a tenant journal under `root`. Files are created with owner-only permissions on Unix.
    pub fn open(root: impl AsRef<Path>, tenant: TenantId) -> Result<Self, HaError> {
        fs::create_dir_all(root.as_ref()).map_err(|_| HaError::StorageUnavailable)?;
        let path = root.as_ref().join(format!("{}.wal", tenant.as_str()));
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|_| HaError::StorageUnavailable)?;
        let recovered = recover_frames(&path, &mut file, &tenant)?;
        Ok(Self {
            tenant,
            path,
            state: Mutex::new(JournalState {
                file,
                committed: recovered.committed,
                pending: recovered.pending,
                next_sequence: recovered.next_sequence,
                last_hash: recovered.last_hash,
                highest_term: recovered.highest_term,
            }),
        })
    }

    /// Tenant namespace owned by this journal.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    /// Local journal path, useful for health checks and backup orchestration.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Return only committed records. Prepared but unresolved entries are never exposed to consumers.
    pub fn committed_records(&self) -> Result<Vec<JournalRecord>, HaError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| HaError::StateUnavailable)?
            .committed
            .clone())
    }
    /// Return pending entries that need consensus reconciliation after a crash/failover.
    pub fn pending_records(&self) -> Result<Vec<JournalRecord>, HaError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| HaError::StateUnavailable)?
            .pending
            .values()
            .cloned()
            .collect())
    }

    fn prepare(&self, term: u64, kind: &str, payload: &[u8]) -> Result<JournalRecord, HaError> {
        if term == 0
            || kind.is_empty()
            || kind.len() > 128
            || !kind.is_ascii()
            || kind.chars().any(char::is_control)
            || payload.len() > MAX_RECORD_BYTES
        {
            return Err(HaError::InvalidRecord);
        }
        let mut state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
        if !state.pending.is_empty() {
            return Err(HaError::UnresolvedTransaction);
        }
        if term < state.highest_term {
            return Err(HaError::NotLeader);
        }
        let sequence = state.next_sequence;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HaError::ClockUnavailable)?
            .as_secs();
        let mut record = JournalRecord {
            tenant: self.tenant.clone(),
            sequence,
            term,
            kind: kind.to_owned(),
            payload: payload.to_vec(),
            previous_hash: state.last_hash,
            hash: [0; 32],
            created_at,
        };
        record.hash = record_hash(&record);
        append_frame(
            &mut state.file,
            &JournalFrame::Prepared {
                record: record.clone(),
            },
        )?;
        state.pending.insert(sequence, record.clone());
        state.highest_term = state.highest_term.max(term);
        state.next_sequence = sequence.checked_add(1).ok_or(HaError::SequenceExhausted)?;
        Ok(record)
    }
    pub fn accept_replica_prepare(&self, record: &JournalRecord) -> Result<(), HaError> {
        if record.tenant != self.tenant || record.hash != record_hash(record) || record.term == 0 {
            return Err(HaError::HashMismatch);
        }
        let mut state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
        if record.term < state.highest_term {
            return Err(HaError::NotLeader);
        }
        if !state.pending.is_empty()
            || record.sequence != state.next_sequence
            || record.previous_hash != state.last_hash
        {
            return Err(HaError::HashMismatch);
        }
        append_frame(
            &mut state.file,
            &JournalFrame::Prepared {
                record: record.clone(),
            },
        )?;
        state.pending.insert(record.sequence, record.clone());
        state.highest_term = state.highest_term.max(record.term);
        state.next_sequence = record
            .sequence
            .checked_add(1)
            .ok_or(HaError::SequenceExhausted)?;
        Ok(())
    }

    fn commit_prepared(&self, sequence: u64, hash: [u8; 32]) -> Result<JournalRecord, HaError> {
        let mut state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
        let record = state
            .pending
            .get(&sequence)
            .ok_or(HaError::TransactionNotFound)?;
        if record.hash != hash {
            return Err(HaError::HashMismatch);
        }
        append_frame(&mut state.file, &JournalFrame::Committed { sequence, hash })?;
        let record = state
            .pending
            .remove(&sequence)
            .ok_or(HaError::TransactionNotFound)?;
        state.last_hash = record.hash;
        state.committed.push(record.clone());
        Ok(record)
    }
    fn abort_prepared(&self, sequence: u64, hash: [u8; 32]) -> Result<(), HaError> {
        let mut state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
        let record = state
            .pending
            .get(&sequence)
            .ok_or(HaError::TransactionNotFound)?;
        if record.hash != hash {
            return Err(HaError::HashMismatch);
        }
        append_frame(&mut state.file, &JournalFrame::Aborted { sequence, hash })?;
        state.pending.remove(&sequence);
        Ok(())
    }

    /// Apply a peer commit decision only if it matches the prepared record's fencing term.
    pub fn accept_replica_commit(
        &self,
        sequence: u64,
        hash: [u8; 32],
        term: u64,
    ) -> Result<(), HaError> {
        {
            let state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
            let record = state
                .pending
                .get(&sequence)
                .ok_or(HaError::TransactionNotFound)?;
            if record.term != term {
                return Err(HaError::NotLeader);
            }
        }
        self.commit_prepared(sequence, hash).map(|_| ())
    }

    /// Apply a peer abort decision only if it matches the prepared record's fencing term.
    pub fn accept_replica_abort(
        &self,
        sequence: u64,
        hash: [u8; 32],
        term: u64,
    ) -> Result<(), HaError> {
        {
            let state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
            let record = state
                .pending
                .get(&sequence)
                .ok_or(HaError::TransactionNotFound)?;
            if record.term != term {
                return Err(HaError::NotLeader);
            }
        }
        self.abort_prepared(sequence, hash)
    }

    /// Write an integrity-checked snapshot using an atomic rename and fsync.
    pub fn write_snapshot(&self, path: impl AsRef<Path>) -> Result<JournalSnapshot, HaError> {
        let state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
        if !state.pending.is_empty() {
            return Err(HaError::UnresolvedTransaction);
        }
        let mut snapshot = JournalSnapshot {
            version: 1,
            tenant: self.tenant.clone(),
            next_sequence: state.next_sequence,
            highest_term: state.highest_term,
            records: state.committed.clone(),
            checksum: [0; 32],
        };
        snapshot.checksum = snapshot_checksum(
            snapshot.version,
            &snapshot.tenant,
            snapshot.next_sequence,
            snapshot.highest_term,
            &snapshot.records,
        )?;
        validate_snapshot(&snapshot, &self.tenant)?;
        let bytes = serde_json::to_vec(&snapshot).map_err(|_| HaError::Encoding)?;
        atomic_write(path.as_ref(), &bytes)?;
        Ok(snapshot)
    }

    /// Restore a validated snapshot into a new, empty journal. Existing data is never overwritten.
    pub fn restore_snapshot(&self, snapshot: &JournalSnapshot) -> Result<(), HaError> {
        validate_snapshot(snapshot, &self.tenant)?;
        {
            let state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
            if !state.committed.is_empty()
                || !state.pending.is_empty()
                || state.next_sequence != 1
                || state.last_hash != [0; 32]
            {
                return Err(HaError::RestoreTargetNotEmpty);
            }
        }
        for record in &snapshot.records {
            let next = self
                .state
                .lock()
                .map_err(|_| HaError::StateUnavailable)?
                .next_sequence;
            if record.sequence > next {
                self.advance_sequence_to(record.sequence)?;
            }
            self.accept_replica_prepare(record)?;
            self.commit_prepared(record.sequence, record.hash)?;
        }
        self.advance_sequence_to(snapshot.next_sequence)?;
        self.advance_fencing_to(snapshot.highest_term)?;
        Ok(())
    }

    /// Load and validate a snapshot file for a specific tenant.
    pub fn read_snapshot(
        path: impl AsRef<Path>,
        tenant: &TenantId,
    ) -> Result<JournalSnapshot, HaError> {
        let bytes = fs::read(path).map_err(|_| HaError::StorageUnavailable)?;
        if bytes.len() > 256 * 1024 * 1024 {
            return Err(HaError::JournalCorrupt);
        }
        let snapshot: JournalSnapshot =
            serde_json::from_slice(&bytes).map_err(|_| HaError::JournalCorrupt)?;
        validate_snapshot(&snapshot, tenant)?;
        Ok(snapshot)
    }

    fn advance_sequence_to(&self, next_sequence: u64) -> Result<(), HaError> {
        let mut state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
        if !state.pending.is_empty() || next_sequence < state.next_sequence {
            return Err(HaError::JournalCorrupt);
        }
        if next_sequence == state.next_sequence {
            return Ok(());
        }
        append_frame(
            &mut state.file,
            &JournalFrame::SequenceAdvance { next_sequence },
        )?;
        state.next_sequence = next_sequence;
        Ok(())
    }

    fn advance_fencing_to(&self, highest_term: u64) -> Result<(), HaError> {
        let mut state = self.state.lock().map_err(|_| HaError::StateUnavailable)?;
        if !state.pending.is_empty() || highest_term < state.highest_term {
            return Err(HaError::JournalCorrupt);
        }
        if highest_term == state.highest_term {
            return Ok(());
        }
        append_frame(
            &mut state.file,
            &JournalFrame::FencingAdvance { highest_term },
        )?;
        state.highest_term = highest_term;
        Ok(())
    }
}

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), HaError> {
    let parent = path.parent().ok_or(HaError::StorageUnavailable)?;
    fs::create_dir_all(parent).map_err(|_| HaError::StorageUnavailable)?;
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("tmp.{}.{}", std::process::id(), counter));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|_| HaError::StorageUnavailable)?;
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(HaError::StorageUnavailable);
    }
    drop(file);
    if fs::rename(&temp, path).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(HaError::StorageUnavailable);
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| HaError::StorageUnavailable)
}

fn append_frame(file: &mut File, frame: &JournalFrame) -> Result<(), HaError> {
    let encoded = serde_json::to_vec(frame).map_err(|_| HaError::Encoding)?;
    if encoded.len() > MAX_RECORD_BYTES * 4 + 4096 {
        return Err(HaError::InvalidRecord);
    }
    file.write_all(&encoded)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_data())
        .map_err(|_| HaError::StorageUnavailable)
}

fn recover_frames(
    path: &Path,
    file: &mut File,
    tenant: &TenantId,
) -> Result<RecoveredFrames, HaError> {
    file.rewind().map_err(|_| HaError::StorageUnavailable)?;
    let reader = BufReader::new(file.try_clone().map_err(|_| HaError::StorageUnavailable)?);
    let mut committed = Vec::new();
    let mut pending: HashMap<u64, JournalRecord> = HashMap::new();
    let mut next_sequence = 1u64;
    let mut last_hash = [0u8; 32];
    let mut highest_term = 0u64;
    for line in reader.lines() {
        let line = line.map_err(|_| HaError::StorageUnavailable)?;
        if line.len() > MAX_RECORD_BYTES * 4 + 4096 {
            return Err(HaError::JournalCorrupt);
        }
        let frame: JournalFrame =
            serde_json::from_str(&line).map_err(|_| HaError::JournalCorrupt)?;
        match frame {
            JournalFrame::Prepared { record } => {
                if record.tenant != *tenant
                    || record.sequence != next_sequence
                    || record.previous_hash != last_hash
                    || record.hash != record_hash(&record)
                    || !pending.is_empty()
                {
                    return Err(HaError::JournalCorrupt);
                }
                next_sequence = next_sequence
                    .checked_add(1)
                    .ok_or(HaError::SequenceExhausted)?;
                highest_term = highest_term.max(record.term);
                pending.insert(record.sequence, record);
            }
            JournalFrame::Committed { sequence, hash } => {
                let record = pending.remove(&sequence).ok_or(HaError::JournalCorrupt)?;
                if record.hash != hash {
                    return Err(HaError::JournalCorrupt);
                }
                last_hash = hash;
                committed.push(record);
            }
            JournalFrame::Aborted { sequence, hash } => {
                let record = pending.remove(&sequence).ok_or(HaError::JournalCorrupt)?;
                if record.hash != hash {
                    return Err(HaError::JournalCorrupt);
                }
            }
            JournalFrame::SequenceAdvance {
                next_sequence: target,
            } => {
                if !pending.is_empty() || target < next_sequence {
                    return Err(HaError::JournalCorrupt);
                }
                next_sequence = target;
            }
            JournalFrame::FencingAdvance {
                highest_term: target,
            } => {
                if !pending.is_empty() || target < highest_term {
                    return Err(HaError::JournalCorrupt);
                }
                highest_term = target;
            }
        }
    }
    let _ = path;
    Ok(RecoveredFrames {
        committed,
        pending,
        next_sequence,
        last_hash,
        highest_term,
    })
}

fn snapshot_checksum(
    version: u32,
    tenant: &TenantId,
    next_sequence: u64,
    highest_term: u64,
    records: &[JournalRecord],
) -> Result<[u8; 32], HaError> {
    let body = SnapshotBody {
        version,
        tenant,
        next_sequence,
        highest_term,
        records,
    };
    let encoded = serde_json::to_vec(&body).map_err(|_| HaError::Encoding)?;
    let mut hasher = Sha256::new();
    hasher.update(b"NEXUSQ-HA-SNAPSHOT-v1\0");
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn validate_snapshot(
    snapshot: &JournalSnapshot,
    expected_tenant: &TenantId,
) -> Result<(), HaError> {
    if snapshot.version != 1
        || snapshot.tenant != *expected_tenant
        || snapshot.next_sequence == 0
        || snapshot.checksum
            != snapshot_checksum(
                snapshot.version,
                &snapshot.tenant,
                snapshot.next_sequence,
                snapshot.highest_term,
                &snapshot.records,
            )?
    {
        return Err(HaError::JournalCorrupt);
    }
    let mut previous_hash = [0u8; 32];
    let mut previous_sequence = 0u64;
    let mut maximum_record_term = 0u64;
    for record in &snapshot.records {
        if record.tenant != snapshot.tenant
            || record.sequence <= previous_sequence
            || record.sequence >= snapshot.next_sequence
            || record.term == 0
            || record.previous_hash != previous_hash
            || record.hash != record_hash(record)
        {
            return Err(HaError::JournalCorrupt);
        }
        previous_sequence = record.sequence;
        previous_hash = record.hash;
        maximum_record_term = maximum_record_term.max(record.term);
    }
    if snapshot.highest_term < maximum_record_term {
        return Err(HaError::JournalCorrupt);
    }
    Ok(())
}

fn record_hash(record: &JournalRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"NEXUSQ-HA-JOURNAL-v1\0");
    hasher.update((record.tenant.as_str().len() as u32).to_be_bytes());
    hasher.update(record.tenant.as_str().as_bytes());
    hasher.update(record.sequence.to_be_bytes());
    hasher.update(record.term.to_be_bytes());
    hasher.update((record.kind.len() as u32).to_be_bytes());
    hasher.update(record.kind.as_bytes());
    hasher.update((record.payload.len() as u64).to_be_bytes());
    hasher.update(&record.payload);
    hasher.update(record.previous_hash);
    hasher.update(record.created_at.to_be_bytes());
    hasher.finalize().into()
}

/// A lease/fencing token supplied by the deployment's consensus-backed control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeadershipLease {
    /// Node that currently holds the lease.
    pub leader_id: String,
    /// Monotonically increasing consensus term.
    pub term: u64,
    /// Lease expiry as UTC Unix seconds.
    pub expires_at: u64,
    /// Monotonic fencing epoch. Must be persisted by the lease provider and never reused.
    pub fencing_epoch: u64,
}
impl LeadershipLease {
    /// Validate that the lease is for this node and is still live.
    pub fn validate(&self, local_node_id: &str, now: SystemTime) -> Result<(), HaError> {
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HaError::ClockUnavailable)?
            .as_secs();
        if self.leader_id != local_node_id
            || self.term == 0
            || self.fencing_epoch == 0
            || now >= self.expires_at
        {
            return Err(HaError::NotLeader);
        }
        Ok(())
    }
}

/// A replica must durably prepare/commit/abort records before acknowledging each operation.
pub trait ReplicaPeer: Send + Sync {
    /// Stable node identity.
    fn node_id(&self) -> &str;
    /// Persist a prepared record and acknowledge only after fsync.
    fn prepare(&self, record: &JournalRecord) -> Result<(), HaError>;
    /// Persist a commit decision for a previously prepared record.
    fn commit(&self, sequence: u64, hash: [u8; 32], term: u64) -> Result<(), HaError>;
    /// Persist an abort decision for a previously prepared record.
    fn abort(&self, sequence: u64, hash: [u8; 32], term: u64) -> Result<(), HaError>;
}

/// HA coordinator with majority prepare and leader-fencing checks.
pub struct HaCoordinator {
    node_id: String,
    journal: Arc<DurableTenantJournal>,
    peers: Vec<Arc<dyn ReplicaPeer>>,
    quorum: usize,
}
impl HaCoordinator {
    /// Create a coordinator. Quorum is computed from this node plus the configured peers.
    pub fn new(
        node_id: impl Into<String>,
        journal: Arc<DurableTenantJournal>,
        peers: Vec<Arc<dyn ReplicaPeer>>,
    ) -> Result<Self, HaError> {
        let node_id = node_id.into();
        if node_id.is_empty() || !node_id.is_ascii() || node_id.chars().any(char::is_control) {
            return Err(HaError::InvalidNodeId);
        }
        if peers.iter().any(|peer| peer.node_id() == node_id) {
            return Err(HaError::DuplicatePeer);
        }
        let mut ids = std::collections::HashSet::new();
        if peers
            .iter()
            .any(|peer| !ids.insert(peer.node_id().to_owned()))
        {
            return Err(HaError::DuplicatePeer);
        }
        let quorum = peers.len().div_ceil(2) + 1;
        Ok(Self {
            node_id,
            journal,
            peers,
            quorum,
        })
    }

    /// Commit a tenant-scoped state mutation. A durable local prepare plus a peer majority is
    /// required before local commit; failures abort the prepared record and never report success.
    pub fn commit(
        &self,
        lease: &LeadershipLease,
        kind: &str,
        payload: &[u8],
    ) -> Result<JournalRecord, HaError> {
        lease.validate(&self.node_id, SystemTime::now())?;
        let record = self.journal.prepare(lease.term, kind, payload)?;
        let mut prepared = 1usize;
        for peer in &self.peers {
            if peer.prepare(&record).is_ok() {
                prepared += 1;
            }
        }
        if prepared < self.quorum {
            let _ = self.journal.abort_prepared(record.sequence, record.hash);
            for peer in &self.peers {
                let _ = peer.abort(record.sequence, record.hash, lease.term);
            }
            return Err(HaError::QuorumUnavailable);
        }
        let committed = self.journal.commit_prepared(record.sequence, record.hash)?;
        let mut acknowledgements = 1usize;
        for peer in &self.peers {
            if peer
                .commit(record.sequence, record.hash, lease.term)
                .is_ok()
            {
                acknowledgements += 1;
            }
        }
        if acknowledgements < self.quorum {
            return Err(HaError::CommitNeedsReconciliation);
        }
        Ok(committed)
    }

    /// Number of acknowledgements required for a write.
    pub fn quorum(&self) -> usize {
        self.quorum
    }
    /// Local node identity.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
    /// Tenant namespace owned by this coordinator.
    pub fn tenant(&self) -> &TenantId {
        self.journal.tenant()
    }
    /// Return the locally committed log for service-state replay on restart.
    pub fn committed_records(&self) -> Result<Vec<JournalRecord>, HaError> {
        self.journal.committed_records()
    }
}

/// Recovery objectives for the deployment. Defaults match issue #69 (RPO <= 1 hour, RTO <= 4 hours).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryObjectives {
    pub max_rpo: Duration,
    pub max_rto: Duration,
}
impl Default for RecoveryObjectives {
    fn default() -> Self {
        Self {
            max_rpo: DEFAULT_RPO,
            max_rto: DEFAULT_RTO,
        }
    }
}
impl RecoveryObjectives {
    /// Reject an objective that is weaker than the requested issue target.
    pub fn validate(&self) -> Result<(), HaError> {
        if self.max_rpo.is_zero()
            || self.max_rpo > DEFAULT_RPO
            || self.max_rto.is_zero()
            || self.max_rto > DEFAULT_RTO
        {
            return Err(HaError::InvalidRecoveryObjectives);
        }
        Ok(())
    }
    /// True if the last confirmed replication point is within the RPO bound.
    pub fn rpo_is_met(&self, last_replicated_at: SystemTime, now: SystemTime) -> bool {
        now.duration_since(last_replicated_at)
            .is_ok_and(|age| age <= self.max_rpo)
    }
    /// True if elapsed recovery time is within the RTO bound.
    pub fn rto_is_met(&self, started_at: SystemTime, now: SystemTime) -> bool {
        now.duration_since(started_at)
            .is_ok_and(|elapsed| elapsed <= self.max_rto)
    }
}

/// Per-tenant rolling-window rate limiter; one noisy tenant cannot consume another tenant's quota.
pub struct TenantRateLimiter {
    window: Duration,
    entries: Mutex<HashMap<TenantId, (SystemTime, u32)>>,
}
impl TenantRateLimiter {
    /// Create a per-tenant limiter.
    pub fn new(window: Duration) -> Result<Self, HaError> {
        if window.is_zero() {
            return Err(HaError::InvalidTenantPolicy);
        }
        Ok(Self {
            window,
            entries: Mutex::new(HashMap::new()),
        })
    }
    /// Return false when this tenant has exhausted its own quota for the current window.
    pub fn allow(&self, tenant: &TenantId, limit: u32, now: SystemTime) -> Result<bool, HaError> {
        if limit == 0 {
            return Err(HaError::InvalidTenantPolicy);
        }
        let mut entries = self.entries.lock().map_err(|_| HaError::StateUnavailable)?;
        let entry = entries.entry(tenant.clone()).or_insert((now, 0));
        let elapsed = match now.duration_since(entry.0) {
            Ok(elapsed) => elapsed,
            Err(_) => return Ok(false),
        };
        if elapsed >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= limit {
            return Ok(false);
        }
        entry.1 += 1;
        Ok(true)
    }
}

/// HA and persistence errors.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum HaError {
    /// Tenant ID is not a safe lowercase identifier.
    #[error("invalid tenant ID")]
    InvalidTenantId,
    /// Tenant already exists.
    #[error("tenant already exists")]
    TenantAlreadyExists,
    /// Tenant not found.
    #[error("tenant not found")]
    TenantNotFound,
    /// Tenant policy is invalid.
    #[error("invalid tenant policy")]
    InvalidTenantPolicy,
    /// State lock is poisoned/unavailable.
    #[error("HA state unavailable")]
    StateUnavailable,
    /// Local durable storage failed.
    #[error("durable journal unavailable")]
    StorageUnavailable,
    /// Journal could not be decoded or its integrity chain failed.
    #[error("journal integrity check failed")]
    JournalCorrupt,
    /// Tenant catalog could not be decoded or contained duplicate/invalid entries.
    #[error("tenant catalog integrity check failed")]
    CatalogCorrupt,
    /// Snapshot restore target already contains state.
    #[error("snapshot restore target is not empty")]
    RestoreTargetNotEmpty,
    /// Record fields exceed limits or are invalid.
    #[error("invalid journal record")]
    InvalidRecord,
    /// Journal has a prepared record requiring failover reconciliation.
    #[error("unresolved prepared transaction; reconcile with the quorum before writing")]
    UnresolvedTransaction,
    /// Transaction not found.
    #[error("prepared transaction not found")]
    TransactionNotFound,
    /// Record hash mismatch.
    #[error("journal record hash mismatch")]
    HashMismatch,
    /// Encoding failed.
    #[error("journal encoding failed")]
    Encoding,
    /// Monotonic sequence exhausted.
    #[error("journal sequence exhausted")]
    SequenceExhausted,
    /// System clock unavailable.
    #[error("system clock unavailable")]
    ClockUnavailable,
    /// Invalid node ID.
    #[error("invalid node ID")]
    InvalidNodeId,
    /// Replica endpoint, TLS material, or peer token is invalid.
    #[error("invalid replica transport configuration")]
    InvalidPeerConfig,
    /// Duplicate peer identity.
    #[error("duplicate replica peer identity")]
    DuplicatePeer,
    /// Caller does not hold a live leader lease.
    #[error("node does not hold a live leader lease")]
    NotLeader,
    /// A majority did not durably prepare the record.
    #[error("replica quorum unavailable")]
    QuorumUnavailable,
    /// Commit was durable locally but needs peer reconciliation before the caller can safely retry.
    #[error("commit needs reconciliation; inspect the journal before retrying")]
    CommitNeedsReconciliation,
    /// RPO/RTO objectives exceed the required limits.
    #[error("recovery objectives exceed RPO 1h / RTO 4h")]
    InvalidRecoveryObjectives,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    use tempfile::tempdir;

    struct FilePeer {
        id: String,
        journal: Arc<DurableTenantJournal>,
        available: AtomicBool,
    }
    impl ReplicaPeer for FilePeer {
        fn node_id(&self) -> &str {
            &self.id
        }
        fn prepare(&self, record: &JournalRecord) -> Result<(), HaError> {
            if !self.available.load(Ordering::SeqCst) {
                return Err(HaError::StorageUnavailable);
            }
            self.journal.accept_replica_prepare(record)
        }
        fn commit(&self, sequence: u64, hash: [u8; 32], _term: u64) -> Result<(), HaError> {
            if !self.available.load(Ordering::SeqCst) {
                return Err(HaError::StorageUnavailable);
            }
            self.journal.accept_replica_commit(sequence, hash, _term)
        }
        fn abort(&self, sequence: u64, hash: [u8; 32], _term: u64) -> Result<(), HaError> {
            if !self.available.load(Ordering::SeqCst) {
                return Err(HaError::StorageUnavailable);
            }
            self.journal.accept_replica_abort(sequence, hash, _term)
        }
    }

    fn live_lease(node: &str, term: u64) -> LeadershipLease {
        LeadershipLease {
            leader_id: node.to_owned(),
            term,
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            fencing_epoch: term,
        }
    }

    #[test]
    fn tenant_ids_and_catalog_are_isolated() {
        assert!(TenantId::new("../tenant").is_err());
        let catalog = TenantCatalog::new();
        let alpha = TenantId::new("alpha").unwrap();
        let beta = TenantId::new("beta").unwrap();
        catalog
            .register(TenantDescriptor {
                id: alpha.clone(),
                ca_certificate_sha256: [1; 32],
                requests_per_minute: 2,
                issuance_enabled: true,
            })
            .unwrap();
        catalog
            .register(TenantDescriptor {
                id: beta.clone(),
                ca_certificate_sha256: [2; 32],
                requests_per_minute: 4,
                issuance_enabled: true,
            })
            .unwrap();
        assert_eq!(catalog.get(&alpha).unwrap().ca_certificate_sha256, [1; 32]);
        assert_eq!(catalog.get(&beta).unwrap().ca_certificate_sha256, [2; 32]);
        catalog.set_issuance(&alpha, false).unwrap();
        assert!(!catalog.get(&alpha).unwrap().issuance_enabled);
        assert!(catalog.get(&beta).unwrap().issuance_enabled);
    }

    #[test]
    fn journal_persists_committed_entries_and_rejects_cross_tenant_records() {
        let dir = tempdir().unwrap();
        let tenant = TenantId::new("alpha").unwrap();
        let journal = DurableTenantJournal::open(dir.path(), tenant.clone()).unwrap();
        let record = journal
            .prepare(1, "certificate.issued", b"serial=1")
            .unwrap();
        assert_eq!(
            journal
                .commit_prepared(record.sequence, record.hash)
                .unwrap(),
            record
        );
        drop(journal);
        let reopened = DurableTenantJournal::open(dir.path(), tenant).unwrap();
        assert_eq!(reopened.committed_records().unwrap().len(), 1);
        assert_eq!(
            reopened.committed_records().unwrap()[0].payload,
            b"serial=1"
        );
    }

    #[test]
    fn tenant_catalog_survives_restart_and_rejects_duplicate_registration() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tenants.json");
        let alpha = TenantId::new("alpha").unwrap();
        {
            let catalog = TenantCatalog::open(&path).unwrap();
            catalog
                .register(TenantDescriptor {
                    id: alpha.clone(),
                    ca_certificate_sha256: [7; 32],
                    requests_per_minute: 10,
                    issuance_enabled: true,
                })
                .unwrap();
            assert!(matches!(
                catalog.register(TenantDescriptor {
                    id: alpha.clone(),
                    ca_certificate_sha256: [8; 32],
                    requests_per_minute: 10,
                    issuance_enabled: true
                }),
                Err(HaError::TenantAlreadyExists)
            ));
            catalog.set_issuance(&alpha, false).unwrap();
        }
        let reopened = TenantCatalog::open(&path).unwrap();
        assert_eq!(reopened.get(&alpha).unwrap().ca_certificate_sha256, [7; 32]);
        assert!(!reopened.get(&alpha).unwrap().issuance_enabled);
    }

    #[test]
    fn snapshot_restores_committed_records_and_sequence_gaps() {
        let dir = tempdir().unwrap();
        let tenant = TenantId::new("alpha").unwrap();
        let source = DurableTenantJournal::open(dir.path().join("source"), tenant.clone()).unwrap();
        let aborted = source.prepare(1, "certificate.issued", b"aborted").unwrap();
        source
            .abort_prepared(aborted.sequence, aborted.hash)
            .unwrap();
        let committed = source
            .prepare(2, "certificate.revoked", b"serial=7")
            .unwrap();
        source
            .commit_prepared(committed.sequence, committed.hash)
            .unwrap();
        let snapshot_path = dir.path().join("snapshot.json");
        let snapshot = source.write_snapshot(&snapshot_path).unwrap();
        let loaded = DurableTenantJournal::read_snapshot(&snapshot_path, &tenant).unwrap();
        assert_eq!(loaded, snapshot);
        let restored =
            DurableTenantJournal::open(dir.path().join("restored"), tenant.clone()).unwrap();
        restored.restore_snapshot(&loaded).unwrap();
        assert_eq!(restored.committed_records().unwrap(), vec![committed]);
        drop(restored);
        let reopened = DurableTenantJournal::open(dir.path().join("restored"), tenant).unwrap();
        assert!(matches!(
            reopened.prepare(1, "crl.published", b"stale-term"),
            Err(HaError::NotLeader)
        ));
        let next = reopened.prepare(2, "crl.published", b"number=8").unwrap();
        assert_eq!(next.sequence, 3);
    }

    #[test]
    fn snapshot_tampering_is_detected() {
        let dir = tempdir().unwrap();
        let tenant = TenantId::new("alpha").unwrap();
        let journal = DurableTenantJournal::open(dir.path(), tenant.clone()).unwrap();
        let record = journal
            .prepare(1, "certificate.issued", b"serial=1")
            .unwrap();
        journal
            .commit_prepared(record.sequence, record.hash)
            .unwrap();
        let path = dir.path().join("snapshot.json");
        journal.write_snapshot(&path).unwrap();
        let mut snapshot = DurableTenantJournal::read_snapshot(&path, &tenant).unwrap();
        snapshot.records[0].payload = b"tampered".to_vec();
        fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        assert!(matches!(
            DurableTenantJournal::read_snapshot(&path, &tenant),
            Err(HaError::JournalCorrupt)
        ));
    }

    #[test]
    fn quorum_and_fencing_are_required_for_mutations() {
        let dir = tempdir().unwrap();
        let tenant = TenantId::new("alpha").unwrap();
        let local =
            Arc::new(DurableTenantJournal::open(dir.path().join("n1"), tenant.clone()).unwrap());
        let peer_journal =
            Arc::new(DurableTenantJournal::open(dir.path().join("n2"), tenant).unwrap());
        let peer = Arc::new(FilePeer {
            id: "n2".into(),
            journal: peer_journal.clone(),
            available: AtomicBool::new(true),
        });
        let coordinator = HaCoordinator::new("n1", local.clone(), vec![peer.clone()]).unwrap();
        assert_eq!(coordinator.quorum(), 2);
        assert!(matches!(
            coordinator.commit(&live_lease("n2", 1), "certificate.issued", b"x"),
            Err(HaError::NotLeader)
        ));
        let record = coordinator
            .commit(&live_lease("n1", 1), "certificate.issued", b"x")
            .unwrap();
        assert_eq!(record.sequence, 1);
        assert_eq!(local.committed_records().unwrap().len(), 1);
        assert_eq!(peer_journal.committed_records().unwrap().len(), 1);
        peer.available.store(false, Ordering::SeqCst);
        assert!(matches!(
            coordinator.commit(&live_lease("n1", 1), "certificate.revoked", b"y"),
            Err(HaError::QuorumUnavailable)
        ));
        assert_eq!(local.committed_records().unwrap().len(), 1);
    }

    #[test]
    fn recovery_objectives_enforce_issue_targets_and_tenant_limits_are_separate() {
        assert!(RecoveryObjectives::default().validate().is_ok());
        assert!(
            RecoveryObjectives {
                max_rpo: Duration::from_secs(7200),
                max_rto: Duration::from_secs(14400)
            }
            .validate()
            .is_err()
        );
        let limiter = TenantRateLimiter::new(Duration::from_secs(60)).unwrap();
        let now = SystemTime::now();
        let alpha = TenantId::new("alpha").unwrap();
        let beta = TenantId::new("beta").unwrap();
        assert!(limiter.allow(&alpha, 1, now).unwrap());
        assert!(!limiter.allow(&alpha, 1, now).unwrap());
        assert!(limiter.allow(&beta, 1, now).unwrap());
    }
}

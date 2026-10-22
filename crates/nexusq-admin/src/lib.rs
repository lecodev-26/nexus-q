//! Administrative security primitives for NexusQ PKI deployments.
//!
//! Includes default-deny RBAC with tenant scopes, an HMAC-authenticated append-only audit log,
//! and Argon2id/XChaCha20-Poly1305 encrypted HA snapshots. Audit keys and backup passphrases must
//! be supplied by an external secret manager; this crate never writes their plaintext to disk.

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use nexusq_ha::{DurableTenantJournal, JournalSnapshot, TenantId};
use rand_core::{OsRng, TryRngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const AUDIT_DOMAIN: &[u8] = b"NEXUSQ-ADMIN-AUDIT-v1\0";
const BACKUP_MAGIC: &[u8; 4] = b"NQAB";
const BACKUP_VERSION: u8 = 1;
const BACKUP_SALT_LEN: usize = 32;
const BACKUP_NONCE_LEN: usize = 24;
const BACKUP_HEADER_LEN: usize = 4 + 1 + BACKUP_SALT_LEN + BACKUP_NONCE_LEN;
const MAX_BACKUP_BYTES: usize = 256 * 1024 * 1024;
const MIN_TOKEN_LEN: usize = 32;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Administrative roles; privilege escalation is blocked when identities are granted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Auditor,
    Operator,
    TenantAdmin,
    BackupAdmin,
    SecurityAdmin,
    RootAdmin,
}
/// Fine-grained permission. Unlisted permissions are denied by default.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ReadHealth,
    ReadAudit,
    Enroll,
    RevokeCertificate,
    PublishCrl,
    ManageTenant,
    CreateBackup,
    RestoreBackup,
    ManageRbac,
    HsmCeremony,
}
impl Role {
    /// Permissions granted by this role.
    pub fn permissions(self) -> &'static [Permission] {
        use Permission::*;
        match self {
            Self::Auditor => &[ReadHealth, ReadAudit],
            Self::Operator => &[ReadHealth, Enroll, RevokeCertificate, PublishCrl],
            Self::TenantAdmin => &[
                ReadHealth,
                Enroll,
                RevokeCertificate,
                PublishCrl,
                ManageTenant,
            ],
            Self::BackupAdmin => &[ReadHealth, ReadAudit, CreateBackup, RestoreBackup],
            Self::SecurityAdmin => &[
                ReadHealth,
                ReadAudit,
                ManageTenant,
                ManageRbac,
                CreateBackup,
                RestoreBackup,
                HsmCeremony,
            ],
            Self::RootAdmin => &[
                ReadHealth,
                ReadAudit,
                Enroll,
                RevokeCertificate,
                PublishCrl,
                ManageTenant,
                CreateBackup,
                RestoreBackup,
                ManageRbac,
                HsmCeremony,
            ],
        }
    }
}

/// Authenticated administrative identity with explicit tenant scopes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdminPrincipal {
    pub subject: String,
    pub roles: BTreeSet<Role>,
    pub tenant_scopes: BTreeSet<TenantId>,
}
impl AdminPrincipal {
    /// True only when a role grants the permission and the tenant is in scope.
    pub fn allows(&self, permission: Permission, tenant: Option<&TenantId>) -> bool {
        if !self
            .roles
            .iter()
            .any(|role| role.permissions().contains(&permission))
        {
            return false;
        }
        if self.roles.contains(&Role::RootAdmin) {
            return true;
        }
        match tenant {
            Some(id) => self.tenant_scopes.contains(id),
            None => {
                permission == Permission::ManageRbac && self.roles.contains(&Role::SecurityAdmin)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredIdentity {
    subject: String,
    token_sha256: [u8; 32],
    roles: BTreeSet<Role>,
    tenant_scopes: BTreeSet<TenantId>,
    enabled: bool,
}

/// Persistent RBAC identity store; only token hashes, never plaintext bearer tokens, are stored.
pub struct RbacStore {
    path: PathBuf,
    identities: RwLock<Vec<StoredIdentity>>,
}
impl RbacStore {
    /// Open or initialize a role-binding store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AdminError> {
        let path = path.as_ref().to_path_buf();
        let identities = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| AdminError::Storage)?;
            let entries: Vec<StoredIdentity> =
                serde_json::from_slice(&bytes).map_err(|_| AdminError::RbacCorrupt)?;
            let mut subjects = HashSet::new();
            if entries.iter().any(|entry| {
                !valid_identifier(&entry.subject)
                    || entry.roles.is_empty()
                    || !subjects.insert(entry.subject.clone())
            }) {
                return Err(AdminError::RbacCorrupt);
            }
            entries
        } else {
            Vec::new()
        };
        let store = Self {
            path,
            identities: RwLock::new(identities),
        };
        store.persist()?;
        Ok(store)
    }

    /// Bootstrap the first root identity; refuses to run once any identity exists.
    pub fn bootstrap_root(
        &self,
        subject: &str,
        token: &str,
        scopes: BTreeSet<TenantId>,
        audit: &AuditLog,
    ) -> Result<(), AdminError> {
        validate_subject_token(subject, token)?;
        let mut entries = self
            .identities
            .write()
            .map_err(|_| AdminError::StateUnavailable)?;
        if !entries.is_empty() {
            return Err(AdminError::BootstrapAlreadyDone);
        }
        audit.append(
            subject,
            AuditAction::RbacBootstrap,
            None,
            AuditOutcome::Requested,
            Some(subject),
        )?;
        entries.push(StoredIdentity {
            subject: subject.to_owned(),
            token_sha256: Sha256::digest(token.as_bytes()).into(),
            roles: BTreeSet::from([Role::RootAdmin]),
            tenant_scopes: scopes,
            enabled: true,
        });
        if let Err(error) = self.persist_locked(&entries) {
            entries.clear();
            return Err(error);
        }
        if audit
            .append(
                subject,
                AuditAction::RbacBootstrap,
                None,
                AuditOutcome::Success,
                Some(subject),
            )
            .is_err()
        {
            entries.clear();
            let _ = self.persist_locked(&entries);
            return Err(AdminError::AuditUnavailable);
        }
        Ok(())
    }

    /// Authenticate an opaque bearer token without storing or logging it.
    pub fn authenticate(&self, token: &str) -> Result<AdminPrincipal, AdminError> {
        if token.len() < MIN_TOKEN_LEN {
            return Err(AdminError::AuthenticationDenied);
        }
        let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let entries = self
            .identities
            .read()
            .map_err(|_| AdminError::StateUnavailable)?;
        for entry in entries.iter().filter(|entry| entry.enabled) {
            if bool::from(actual.ct_eq(&entry.token_sha256)) {
                return Ok(AdminPrincipal {
                    subject: entry.subject.clone(),
                    roles: entry.roles.clone(),
                    tenant_scopes: entry.tenant_scopes.clone(),
                });
            }
        }
        Err(AdminError::AuthenticationDenied)
    }

    /// Grant a new identity, enforcing role hierarchy and tenant-scope restrictions.
    pub fn grant(
        &self,
        actor: &AdminPrincipal,
        subject: &str,
        token: &str,
        roles: BTreeSet<Role>,
        scopes: BTreeSet<TenantId>,
        audit: &AuditLog,
    ) -> Result<(), AdminError> {
        validate_subject_token(subject, token)?;
        if roles.is_empty() || !actor.allows(Permission::ManageRbac, None) {
            return Err(AdminError::AuthorizationDenied);
        }
        if !actor.roles.contains(&Role::RootAdmin)
            && roles
                .iter()
                .any(|role| matches!(role, Role::SecurityAdmin | Role::RootAdmin))
        {
            return Err(AdminError::AuthorizationDenied);
        }
        if !actor.roles.contains(&Role::RootAdmin) && !scopes.is_subset(&actor.tenant_scopes) {
            return Err(AdminError::AuthorizationDenied);
        }
        let mut entries = self
            .identities
            .write()
            .map_err(|_| AdminError::StateUnavailable)?;
        if entries.iter().any(|entry| entry.subject == subject) {
            return Err(AdminError::IdentityExists);
        }
        audit.append(
            &actor.subject,
            AuditAction::RbacGrant,
            None,
            AuditOutcome::Requested,
            Some(subject),
        )?;
        entries.push(StoredIdentity {
            subject: subject.to_owned(),
            token_sha256: Sha256::digest(token.as_bytes()).into(),
            roles,
            tenant_scopes: scopes,
            enabled: true,
        });
        if let Err(error) = self.persist_locked(&entries) {
            entries.retain(|entry| entry.subject != subject);
            return Err(error);
        }
        if audit
            .append(
                &actor.subject,
                AuditAction::RbacGrant,
                None,
                AuditOutcome::Success,
                Some(subject),
            )
            .is_err()
        {
            entries.retain(|entry| entry.subject != subject);
            let _ = self.persist_locked(&entries);
            return Err(AdminError::AuditUnavailable);
        }
        Ok(())
    }

    /// Disable an identity; the last enabled root cannot be revoked.
    pub fn revoke(
        &self,
        actor: &AdminPrincipal,
        subject: &str,
        audit: &AuditLog,
    ) -> Result<(), AdminError> {
        if !actor.allows(Permission::ManageRbac, None) {
            return Err(AdminError::AuthorizationDenied);
        }
        let mut entries = self
            .identities
            .write()
            .map_err(|_| AdminError::StateUnavailable)?;
        let index = entries
            .iter()
            .position(|entry| entry.subject == subject && entry.enabled)
            .ok_or(AdminError::IdentityNotFound)?;
        if entries[index].roles.contains(&Role::RootAdmin)
            && entries
                .iter()
                .filter(|entry| entry.enabled && entry.roles.contains(&Role::RootAdmin))
                .count()
                == 1
        {
            return Err(AdminError::LastRootIdentity);
        }
        audit.append(
            &actor.subject,
            AuditAction::RbacRevoke,
            None,
            AuditOutcome::Requested,
            Some(subject),
        )?;
        entries[index].enabled = false;
        if let Err(error) = self.persist_locked(&entries) {
            entries[index].enabled = true;
            return Err(error);
        }
        if audit
            .append(
                &actor.subject,
                AuditAction::RbacRevoke,
                None,
                AuditOutcome::Success,
                Some(subject),
            )
            .is_err()
        {
            entries[index].enabled = true;
            let _ = self.persist_locked(&entries);
            return Err(AdminError::AuditUnavailable);
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), AdminError> {
        let entries = self
            .identities
            .read()
            .map_err(|_| AdminError::StateUnavailable)?;
        self.persist_locked(&entries)
    }
    fn persist_locked(&self, entries: &[StoredIdentity]) -> Result<(), AdminError> {
        atomic_write(
            &self.path,
            &serde_json::to_vec(entries).map_err(|_| AdminError::Encoding)?,
            false,
        )
    }
}

fn validate_subject_token(subject: &str, token: &str) -> Result<(), AdminError> {
    if !valid_identifier(subject)
        || token.len() < MIN_TOKEN_LEN
        || token.chars().any(char::is_control)
    {
        return Err(AdminError::InvalidIdentity);
    }
    Ok(())
}
fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && !value.chars().any(char::is_control)
}

/// Operational audit action. The schema intentionally has no free-form details field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    RbacBootstrap,
    RbacGrant,
    RbacRevoke,
    TenantIssuanceChanged,
    TenantStatusRead,
    BackupCreated,
    BackupRestored,
    CertificateIssued,
    CertificateRevoked,
    OcspQuery,
    CrlRead,
    CrlPublished,
    HsmCeremony,
    AuthorizationDenied,
    AdminLogin,
}
/// Outcome of an administrative action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Requested,
    Success,
    Denied,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AuditBody {
    sequence: u64,
    timestamp_unix_secs: u64,
    actor: String,
    action: AuditAction,
    tenant: Option<TenantId>,
    outcome: AuditOutcome,
    resource_id: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AuditRecord {
    body: AuditBody,
    previous_hash: [u8; 32],
    hash: [u8; 32],
    mac: [u8; 32],
}
struct AuditState {
    file: File,
    sequence: u64,
    head_hash: [u8; 32],
    poisoned: bool,
}

/// HMAC-authenticated append-only audit log. The key must come from a secret manager/KMS.
pub struct AuditLog {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    state: Mutex<AuditState>,
}
impl AuditLog {
    /// Open/create an audit log and verify its complete chain before accepting writes.
    pub fn open(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, AdminError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|_| AdminError::Storage)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|_| AdminError::Storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = file.metadata().map_err(|_| AdminError::Storage)?;
            if metadata.permissions().mode() & 0o077 != 0 {
                file.set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|_| AdminError::Storage)?;
            }
        }
        let (sequence, head_hash) = verify_audit_file(&mut file, &key)?;
        Ok(Self {
            path,
            key: Zeroizing::new(key),
            state: Mutex::new(AuditState {
                file,
                sequence,
                head_hash,
                poisoned: false,
            }),
        })
    }

    /// Append a safe structured event and fsync it before returning.
    pub fn append(
        &self,
        actor: &str,
        action: AuditAction,
        tenant: Option<&TenantId>,
        outcome: AuditOutcome,
        resource_id: Option<&str>,
    ) -> Result<(), AdminError> {
        if !valid_identifier(actor) || resource_id.is_some_and(|value| !valid_identifier(value)) {
            return Err(AdminError::InvalidAuditEvent);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| AdminError::StateUnavailable)?;
        if state.poisoned {
            return Err(AdminError::AuditUnavailable);
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AdminError::ClockUnavailable)?
            .as_secs();
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or(AdminError::SequenceExhausted)?;
        let body = AuditBody {
            sequence,
            timestamp_unix_secs: timestamp,
            actor: actor.to_owned(),
            action,
            tenant: tenant.cloned(),
            outcome,
            resource_id: resource_id.map(str::to_owned),
        };
        let previous_hash = state.head_hash;
        let hash = audit_hash(&body, &previous_hash)?;
        let mac = audit_mac(&self.key, &previous_hash, &hash)?;
        let record = AuditRecord {
            body,
            previous_hash,
            hash,
            mac,
        };
        let mut bytes = serde_json::to_vec(&record).map_err(|_| AdminError::Encoding)?;
        bytes.push(b'\n');
        if state
            .file
            .write_all(&bytes)
            .and_then(|_| state.file.sync_data())
            .is_err()
        {
            // A partial append may have left a truncated record. Fail closed until the log is
            // inspected/recovered instead of appending behind an unverifiable tail.
            state.poisoned = true;
            return Err(AdminError::AuditUnavailable);
        }
        state.sequence = sequence;
        state.head_hash = hash;
        Ok(())
    }

    /// Verify the on-disk audit chain without modifying it.
    pub fn verify(&self) -> Result<(), AdminError> {
        let mut file = File::open(&self.path).map_err(|_| AdminError::Storage)?;
        verify_audit_file(&mut file, &self.key).map(|_| ())
    }
    /// Return the last event hash for a separately protected integrity anchor.
    pub fn head_hash(&self) -> Result<[u8; 32], AdminError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| AdminError::StateUnavailable)?
            .head_hash)
    }
}

fn verify_audit_file(file: &mut File, key: &[u8; 32]) -> Result<(u64, [u8; 32]), AdminError> {
    use std::io::Seek;
    file.rewind().map_err(|_| AdminError::Storage)?;
    let reader = BufReader::new(file.try_clone().map_err(|_| AdminError::Storage)?);
    let mut sequence = 0u64;
    let mut head = [0u8; 32];
    for line in reader.lines() {
        let line = line.map_err(|_| AdminError::Storage)?;
        if line.len() > 1024 * 1024 {
            return Err(AdminError::AuditIntegrity);
        }
        let record: AuditRecord =
            serde_json::from_str(&line).map_err(|_| AdminError::AuditIntegrity)?;
        if record.body.sequence != sequence + 1
            || record.previous_hash != head
            || record.hash != audit_hash(&record.body, &head)?
            || record.mac != audit_mac(key, &head, &record.hash)?
        {
            return Err(AdminError::AuditIntegrity);
        }
        sequence = record.body.sequence;
        head = record.hash;
    }
    Ok((sequence, head))
}
fn audit_hash(body: &AuditBody, previous_hash: &[u8; 32]) -> Result<[u8; 32], AdminError> {
    let encoded = serde_json::to_vec(body).map_err(|_| AdminError::Encoding)?;
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_DOMAIN);
    hasher.update(previous_hash);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}
fn audit_mac(
    key: &[u8; 32],
    previous_hash: &[u8; 32],
    hash: &[u8; 32],
) -> Result<[u8; 32], AdminError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| AdminError::Encoding)?;
    mac.update(AUDIT_DOMAIN);
    mac.update(previous_hash);
    mac.update(hash);
    Ok(mac.finalize().into_bytes().into())
}

/// Export a validated HA snapshot to an Argon2id/XChaCha20-Poly1305 encrypted backup.
pub fn export_encrypted_snapshot(
    snapshot: &JournalSnapshot,
    tenant: &TenantId,
    backup_path: impl AsRef<Path>,
    passphrase: &[u8],
) -> Result<(), AdminError> {
    snapshot
        .validate_for_tenant(tenant)
        .map_err(|_| AdminError::BackupIntegrity)?;
    if passphrase.len() < 12 {
        return Err(AdminError::WeakPassphrase);
    }
    let plaintext = Zeroizing::new(serde_json::to_vec(snapshot).map_err(|_| AdminError::Encoding)?);
    if plaintext.len() > MAX_BACKUP_BYTES {
        return Err(AdminError::BackupTooLarge);
    }
    let mut salt = [0u8; BACKUP_SALT_LEN];
    let mut nonce = [0u8; BACKUP_NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| AdminError::Randomness)?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| AdminError::Randomness)?;
    let key = derive_backup_key(passphrase, &salt)?;
    let mut header = Vec::with_capacity(BACKUP_HEADER_LEN);
    header.extend_from_slice(BACKUP_MAGIC);
    header.push(BACKUP_VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| AdminError::Encoding)?;
    let nonce_for_aead = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce_for_aead,
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| AdminError::BackupIntegrity)?;
    let mut output = header;
    output.extend_from_slice(&ciphertext);
    atomic_write(backup_path.as_ref(), &output, true)
}

/// Decrypt and validate a tenant-specific snapshot backup.
pub fn import_encrypted_snapshot(
    backup_path: impl AsRef<Path>,
    tenant: &TenantId,
    passphrase: &[u8],
) -> Result<JournalSnapshot, AdminError> {
    if passphrase.len() < 12 {
        return Err(AdminError::WeakPassphrase);
    }
    let bytes = fs::read(backup_path).map_err(|_| AdminError::Storage)?;
    if bytes.len() < BACKUP_HEADER_LEN + 16
        || bytes.len() > MAX_BACKUP_BYTES + BACKUP_HEADER_LEN + 16
        || &bytes[..4] != BACKUP_MAGIC
        || bytes[4] != BACKUP_VERSION
    {
        return Err(AdminError::BackupIntegrity);
    }
    let salt = &bytes[5..5 + BACKUP_SALT_LEN];
    let nonce_start = 5 + BACKUP_SALT_LEN;
    let nonce = &bytes[nonce_start..nonce_start + BACKUP_NONCE_LEN];
    let key = derive_backup_key(passphrase, salt)?;
    let nonce_array: [u8; BACKUP_NONCE_LEN] =
        nonce.try_into().map_err(|_| AdminError::BackupIntegrity)?;
    let nonce_for_aead = XNonce::from(nonce_array);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| AdminError::Encoding)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce_for_aead,
                Payload {
                    msg: &bytes[BACKUP_HEADER_LEN..],
                    aad: &bytes[..BACKUP_HEADER_LEN],
                },
            )
            .map_err(|_| AdminError::WrongPassphraseOrCorrupt)?,
    );
    let snapshot: JournalSnapshot =
        serde_json::from_slice(&plaintext).map_err(|_| AdminError::BackupIntegrity)?;
    snapshot
        .validate_for_tenant(tenant)
        .map_err(|_| AdminError::BackupIntegrity)?;
    Ok(snapshot)
}

/// Permission-enforcing tenant backup catalogue. It never accepts arbitrary filesystem paths from callers.
pub struct BackupManager {
    root: PathBuf,
}
impl BackupManager {
    /// Create a backup catalogue rooted in a directory writable only by the NexusQ service account.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, AdminError> {
        fs::create_dir_all(root.as_ref()).map_err(|_| AdminError::Storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.as_ref(), fs::Permissions::from_mode(0o700))
                .map_err(|_| AdminError::Storage)?;
        }
        Ok(Self {
            root: root.as_ref().to_path_buf(),
        })
    }

    /// Create an encrypted tenant backup after checking RBAC and recording the operation.
    /// Returns only the opaque backup ID, not a filesystem path.
    pub fn create(
        &self,
        principal: &AdminPrincipal,
        snapshot: &JournalSnapshot,
        tenant: &TenantId,
        passphrase: &[u8],
        audit: &AuditLog,
    ) -> Result<String, AdminError> {
        if !principal.allows(Permission::CreateBackup, Some(tenant)) {
            let _ = audit.append(
                &principal.subject,
                AuditAction::AuthorizationDenied,
                Some(tenant),
                AuditOutcome::Denied,
                Some("backup-create"),
            );
            return Err(AdminError::AuthorizationDenied);
        }
        snapshot
            .validate_for_tenant(tenant)
            .map_err(|_| AdminError::BackupIntegrity)?;
        audit.append(
            &principal.subject,
            AuditAction::BackupCreated,
            Some(tenant),
            AuditOutcome::Requested,
            Some("backup-create"),
        )?;
        let directory = self.tenant_directory(tenant);
        fs::create_dir_all(&directory).map_err(|_| AdminError::Storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| AdminError::Storage)?;
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AdminError::ClockUnavailable)?
            .as_secs();
        let mut random = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| AdminError::Randomness)?;
        let random_hex = random.iter().fold(
            String::with_capacity(random.len() * 2),
            |mut output, byte| {
                let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"));
                output
            },
        );
        let backup_id = format!("backup-{timestamp}-{random_hex}.nqab");
        let path = directory.join(&backup_id);
        export_encrypted_snapshot(snapshot, tenant, &path, passphrase)?;
        if audit
            .append(
                &principal.subject,
                AuditAction::BackupCreated,
                Some(tenant),
                AuditOutcome::Success,
                Some(&backup_id),
            )
            .is_err()
        {
            let _ = fs::remove_file(&path);
            return Err(AdminError::AuditUnavailable);
        }
        Ok(backup_id)
    }

    /// Load and authenticate a named backup. Backup IDs cannot contain path separators.
    pub fn load(
        &self,
        principal: &AdminPrincipal,
        tenant: &TenantId,
        backup_id: &str,
        passphrase: &[u8],
        audit: &AuditLog,
    ) -> Result<JournalSnapshot, AdminError> {
        if !principal.allows(Permission::RestoreBackup, Some(tenant)) {
            let _ = audit.append(
                &principal.subject,
                AuditAction::AuthorizationDenied,
                Some(tenant),
                AuditOutcome::Denied,
                Some("backup-restore"),
            );
            return Err(AdminError::AuthorizationDenied);
        }
        if !valid_backup_id(backup_id) {
            return Err(AdminError::BackupIntegrity);
        }
        audit.append(
            &principal.subject,
            AuditAction::BackupRestored,
            Some(tenant),
            AuditOutcome::Requested,
            Some(backup_id),
        )?;
        let snapshot = import_encrypted_snapshot(
            self.tenant_directory(tenant).join(backup_id),
            tenant,
            passphrase,
        )?;
        audit.append(
            &principal.subject,
            AuditAction::BackupRestored,
            Some(tenant),
            AuditOutcome::Success,
            Some(backup_id),
        )?;
        Ok(snapshot)
    }

    /// Restore an authorized backup into an empty tenant journal; existing journal data is never overwritten.
    pub fn restore_into(
        &self,
        principal: &AdminPrincipal,
        tenant: &TenantId,
        backup_id: &str,
        passphrase: &[u8],
        journal: &DurableTenantJournal,
        audit: &AuditLog,
    ) -> Result<(), AdminError> {
        if !principal.allows(Permission::RestoreBackup, Some(tenant)) {
            let _ = audit.append(
                &principal.subject,
                AuditAction::AuthorizationDenied,
                Some(tenant),
                AuditOutcome::Denied,
                Some("backup-restore"),
            );
            return Err(AdminError::AuthorizationDenied);
        }
        if !valid_backup_id(backup_id) {
            return Err(AdminError::BackupIntegrity);
        }
        audit.append(
            &principal.subject,
            AuditAction::BackupRestored,
            Some(tenant),
            AuditOutcome::Requested,
            Some(backup_id),
        )?;
        let snapshot = import_encrypted_snapshot(
            self.tenant_directory(tenant).join(backup_id),
            tenant,
            passphrase,
        )?;
        journal
            .restore_snapshot(&snapshot)
            .map_err(|_| AdminError::BackupIntegrity)?;
        audit.append(
            &principal.subject,
            AuditAction::BackupRestored,
            Some(tenant),
            AuditOutcome::Success,
            Some(backup_id),
        )?;
        Ok(())
    }

    fn tenant_directory(&self, tenant: &TenantId) -> PathBuf {
        let digest = Sha256::digest(tenant.as_str().as_bytes());
        let name = digest.iter().fold(
            String::with_capacity(digest.len() * 2),
            |mut output, byte| {
                let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"));
                output
            },
        );
        self.root.join(name)
    }
}
fn valid_backup_id(value: &str) -> bool {
    value.len() <= 128
        && value.starts_with("backup-")
        && value.ends_with(".nqab")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        && !value.contains("..")
}

fn derive_backup_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, AdminError> {
    let params = Argon2Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| AdminError::Encoding)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| AdminError::Encoding)?;
    Ok(key)
}

fn atomic_write(path: &Path, bytes: &[u8], no_replace: bool) -> Result<(), AdminError> {
    if bytes.len() > MAX_BACKUP_BYTES + BACKUP_HEADER_LEN + 16 {
        return Err(AdminError::BackupTooLarge);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|_| AdminError::Storage)?;
    let temp = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|_| AdminError::Storage)?;
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(AdminError::Storage);
    }
    drop(file);
    let result = if no_replace {
        fs::hard_link(&temp, path)
    } else {
        fs::rename(&temp, path)
    };
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        return Err(if no_replace && path.exists() {
            AdminError::BackupAlreadyExists
        } else {
            AdminError::Storage
        });
    }
    let _ = fs::remove_file(&temp);
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AdminError::Storage)
}

/// Administrative security errors.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AdminError {
    #[error("storage operation failed")]
    Storage,
    #[error("administrative state unavailable")]
    StateUnavailable,
    #[error("RBAC store is corrupt")]
    RbacCorrupt,
    #[error("root identity has already been bootstrapped")]
    BootstrapAlreadyDone,
    #[error("authentication denied")]
    AuthenticationDenied,
    #[error("authorization denied")]
    AuthorizationDenied,
    #[error("invalid identity or token policy")]
    InvalidIdentity,
    #[error("identity already exists")]
    IdentityExists,
    #[error("identity not found")]
    IdentityNotFound,
    #[error("cannot revoke the last enabled root identity")]
    LastRootIdentity,
    #[error("audit event is invalid")]
    InvalidAuditEvent,
    #[error("audit log integrity verification failed")]
    AuditIntegrity,
    #[error("audit log unavailable")]
    AuditUnavailable,
    #[error("system clock unavailable")]
    ClockUnavailable,
    #[error("sequence exhausted")]
    SequenceExhausted,
    #[error("backup passphrase is too short")]
    WeakPassphrase,
    #[error("backup file already exists")]
    BackupAlreadyExists,
    #[error("backup is too large")]
    BackupTooLarge,
    #[error("backup integrity verification failed")]
    BackupIntegrity,
    #[error("wrong passphrase or corrupted backup")]
    WrongPassphraseOrCorrupt,
    #[error("secure randomness unavailable")]
    Randomness,
    #[error("encoding or cryptographic setup failed")]
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexusq_ha::DurableTenantJournal;

    fn token(prefix: &str) -> String {
        format!("{prefix}-{}", "x".repeat(48))
    }

    #[test]
    fn rbac_is_default_deny_tenant_scoped_and_blocks_privilege_escalation() {
        let dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::open(dir.path().join("audit.log"), [9; 32]).unwrap();
        let store = RbacStore::open(dir.path().join("rbac.json")).unwrap();
        let alpha = TenantId::new("alpha").unwrap();
        let beta = TenantId::new("beta").unwrap();
        let root_token = token("root");
        store
            .bootstrap_root(
                "root",
                &root_token,
                BTreeSet::from([alpha.clone(), beta.clone()]),
                &audit,
            )
            .unwrap();
        let root = store.authenticate(&root_token).unwrap();
        let operator_token = token("operator");
        store
            .grant(
                &root,
                "operator",
                &operator_token,
                BTreeSet::from([Role::Operator]),
                BTreeSet::from([alpha.clone()]),
                &audit,
            )
            .unwrap();
        let operator = store.authenticate(&operator_token).unwrap();
        assert!(operator.allows(Permission::RevokeCertificate, Some(&alpha)));
        assert!(!operator.allows(Permission::RevokeCertificate, Some(&beta)));
        assert!(!operator.allows(Permission::ManageRbac, None));
        let elevated = store.grant(
            &operator,
            "escalated",
            &token("escalated"),
            BTreeSet::from([Role::RootAdmin]),
            BTreeSet::from([alpha]),
            &audit,
        );
        assert!(matches!(elevated, Err(AdminError::AuthorizationDenied)));
        assert!(matches!(
            store.authenticate("short"),
            Err(AdminError::AuthenticationDenied)
        ));
        audit.verify().unwrap();
    }

    #[test]
    fn audit_chain_detects_tampering_and_rejects_control_characters() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let audit = AuditLog::open(&path, [7; 32]).unwrap();
        audit
            .append(
                "admin-1",
                AuditAction::AdminLogin,
                None,
                AuditOutcome::Success,
                Some("session-1"),
            )
            .unwrap();
        assert!(matches!(
            audit.append(
                "admin\nvalue",
                AuditAction::AdminLogin,
                None,
                AuditOutcome::Success,
                None
            ),
            Err(AdminError::InvalidAuditEvent)
        ));
        drop(audit);
        let mut bytes = fs::read(&path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            AuditLog::open(&path, [7; 32]),
            Err(AdminError::AuditIntegrity)
        ));
    }

    #[test]
    fn backup_manager_enforces_rbac_and_rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = TenantId::new("tenant-blue").unwrap();
        let other = TenantId::new("tenant-red").unwrap();
        let journal =
            DurableTenantJournal::open(dir.path().join("journal"), tenant.clone()).unwrap();
        let snapshot = journal
            .write_snapshot(dir.path().join("snapshot.json"))
            .unwrap();
        let audit = AuditLog::open(dir.path().join("audit.log"), [3; 32]).unwrap();
        let manager = BackupManager::new(dir.path().join("backups")).unwrap();
        let principal = AdminPrincipal {
            subject: "backup-operator".into(),
            roles: BTreeSet::from([Role::BackupAdmin]),
            tenant_scopes: BTreeSet::from([tenant.clone()]),
        };
        let password = b"backup-passphrase-long-enough";
        let backup_id = manager
            .create(&principal, &snapshot, &tenant, password, &audit)
            .unwrap();
        assert!(valid_backup_id(&backup_id));
        assert_eq!(
            manager
                .load(&principal, &tenant, &backup_id, password, &audit)
                .unwrap(),
            snapshot
        );
        assert!(matches!(
            manager.load(&principal, &tenant, "../../audit.log", password, &audit),
            Err(AdminError::BackupIntegrity)
        ));
        assert!(matches!(
            manager.create(&principal, &snapshot, &other, password, &audit),
            Err(AdminError::AuthorizationDenied)
        ));
        audit.verify().unwrap();
    }

    #[test]
    fn encrypted_snapshot_roundtrips_and_rejects_wrong_passphrase_and_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = TenantId::new("alpha").unwrap();
        let journal =
            DurableTenantJournal::open(dir.path().join("journal"), tenant.clone()).unwrap();
        let snapshot_path = dir.path().join("snapshot.json");
        let snapshot = journal.write_snapshot(&snapshot_path).unwrap();
        let backup_path = dir.path().join("tenant.nqab");
        let password = b"a-long-backup-passphrase-for-tests";
        export_encrypted_snapshot(&snapshot, &tenant, &backup_path, password).unwrap();
        assert_eq!(
            import_encrypted_snapshot(&backup_path, &tenant, password).unwrap(),
            snapshot
        );
        assert!(matches!(
            import_encrypted_snapshot(&backup_path, &tenant, b"wrong-passphrase-long"),
            Err(AdminError::WrongPassphraseOrCorrupt)
        ));
        assert!(matches!(
            import_encrypted_snapshot(&backup_path, &TenantId::new("beta").unwrap(), password),
            Err(AdminError::BackupIntegrity)
        ));
        assert!(matches!(
            export_encrypted_snapshot(&snapshot, &tenant, &backup_path, password),
            Err(AdminError::BackupAlreadyExists)
        ));
    }
}

//! Backup bundles (format F-05).
//!
//! A backup bundle is a self-contained file that captures a vault's
//! entire content, protected by a passphrase **separate** from the
//! vault's own password. Two reasons for the separation:
//!
//! 1. If the vault password leaks, the backup is still protected.
//! 2. If the backup file leaks, the vault is still protected.
//!
//! ## Wire format
//!
//! ```text
//! [magic \"NQB1\"][version 2][header_cbor_len u32 BE]
//! [header_cbor: N bytes]
//! [body_nonce: 12 bytes]
//! [body_ciphertext_and_tag: M bytes]
//! ```
//!
//! The header is CBOR and carries the KDF parameters, the salt and a
//! KEK verifier computed with a distinct info string
//! (`nexusq-backup-kek-check`), so that a vault password can never be
//! confused with a backup passphrase.
//!
//! ## What a backup contains
//!
//! The full [`VaultBody`]: every key record (including the wrapped
//! private material), every identity, and the vault metadata. The
//! body is encrypted with a KEK derived from the backup passphrase.
//!
//! ## What a backup does not contain
//!
//! - The vault's own password or derived KEK.
//! - The audit log. Auditing is a separate file; deployments that
//!   want both back them up independently.
//!
//! ## Restore
//!
//! Importing creates a **new** vault: fresh salt, new vault password,
//! all key material re-wrapped under the new KEK. The vault id is
//! preserved because it identifies the logical vault, not the file.
//!
//! See `docs/STORAGE.md` §8.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::aead::{self, AeadError, Algorithm as AeadAlgorithm};
use crate::crypto::kdf::{self, KdfError};
use crate::crypto::random::{OsRandomSource, RandomError, RandomSource};
use crate::vault::body::VaultBody;
use crate::vault::header::{HeaderError, KdfAlgorithm, KdfParams};
use crate::vault::operation::{
    OperationControl, OperationError, OperationPhase, OperationProgress,
};
use crate::vault::serde_helpers::{self, CborError};
use crate::vault::{Session, Vault, VaultError};

/// File magic for the backup bundle format.
pub const MAGIC: [u8; 4] = *b"NQB1";

/// Current format version.
pub const FORMAT_VERSION: u8 = 2;

/// Length in bytes of the backup salt.
pub const SALT_LEN: usize = 32;

/// Length in bytes of the KEK verifier.
pub const KEK_VERIFIER_LEN: usize = 32;

/// Length in bytes of the body nonce.
pub const BODY_NONCE_LEN: usize = aead::NONCE_LEN;

/// Info string for the backup KEK verifier.
///
/// Deliberately different from the vault's so that a backup
/// passphrase can never be mistaken for a vault password.
const BACKUP_KEK_VERIFIER_INFO: &[u8] = b"nexusq-backup-kek-check";

/// Length in bytes of the length prefix before the CBOR header.
const HEADER_LEN_PREFIX: usize = 4;

/// The header of a backup bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupHeader {
    /// File magic: always [`MAGIC`].
    pub magic: [u8; 4],

    /// Format version: always [`FORMAT_VERSION`] for v1.
    pub version: u8,

    /// Reserved flags. Must be zero in v1.
    pub flags: u16,

    /// Key derivation parameters.
    pub kdf: KdfParams,

    /// Random salt, unique per backup.
    pub salt: Vec<u8>,

    /// Verifier for the derived backup KEK.
    pub kek_verifier: [u8; KEK_VERIFIER_LEN],
}

impl BackupHeader {
    /// Returns `true` if the header's magic, version and flags match
    /// what this build supports.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.magic == MAGIC && self.version == FORMAT_VERSION && self.flags == 0
    }
}

/// Errors returned by backup operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    /// An I/O error occurred.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The backup header was malformed or used an unsupported version.
    #[error("header error: {0}")]
    Header(#[from] HeaderError),

    /// CBOR (de)serialization failed.
    #[error("cbor error: {0}")]
    Cbor(#[from] CborError),

    /// AEAD encryption or decryption failed.
    #[error("aead error: {0}")]
    Aead(#[from] AeadError),

    /// Key derivation failed.
    #[error("kdf error: {0}")]
    Kdf(#[from] KdfError),

    /// Randomness generation failed.
    #[error("random error: {0}")]
    Random(#[from] RandomError),

    /// The backup passphrase is incorrect.
    #[error("wrong backup passphrase")]
    WrongPassphrase,

    /// The file was not produced by this program.
    #[error("invalid backup magic number")]
    BadMagic,

    /// The backup uses a version this build does not understand.
    #[error("unsupported backup version: {0}")]
    UnsupportedVersion(u8),

    /// The file is malformed or truncated.
    #[error("backup file is corrupted: {0}")]
    Corrupt(&'static str),

    /// A vault operation failed during export or import.
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
}

// =============================================================================
// Export
// =============================================================================

/// Exports the vault's content to a backup file protected by
/// `backup_passphrase`.
///
/// The session must be unlocked: exporting needs the vault's KEK to
/// read the body.
///
/// # Errors
///
/// Returns [`BackupError::Io`] if the file cannot be written, or
/// another backup error if derivation, serialization or encryption
/// fails.
pub fn export(
    session: &Session,
    backup_path: impl AsRef<Path>,
    backup_passphrase: &[u8],
) -> Result<(), BackupError> {
    let backup_path = backup_path.as_ref();

    let rng = OsRandomSource::new();

    // Fresh salt and nonce.
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt)?;

    let mut nonce = [0u8; BODY_NONCE_LEN];
    rng.fill_bytes(&mut nonce)?;

    // Derive the backup KEK and build the header.
    let params = KdfParams::v1_default();
    let backup_kek = derive_backup_kek(backup_passphrase, &salt, &params)?;
    let header = build_header(params, salt.to_vec(), backup_kek.as_ref())?;

    // Re-wrap key records under the backup KEK before serializing. This
    // makes the backup self-contained: import can safely re-wrap them
    // again under the newly created vault KEK.
    let backup_body = session.clone_body_rewrapped(backup_kek.as_ref())?;
    let body_bytes = Zeroizing::new(serde_helpers::to_vec(&backup_body)?);
    let header_bytes = serde_helpers::to_vec(&header)?;

    // Encrypt with the header as AAD.
    let ciphertext = aead::encrypt(
        AeadAlgorithm::Aes256Gcm,
        backup_kek.as_ref(),
        &nonce,
        &header_bytes,
        &body_bytes,
    )?;

    write_backup_file(backup_path, &header_bytes, &nonce, &ciphertext)?;
    Ok(())
}

/// Export a backup with cooperative cancellation and backend phase updates.
/// The destination is published create-only; an existing file is never replaced.
pub fn export_controlled(
    session: &Session,
    backup_path: impl AsRef<Path>,
    backup_passphrase: &[u8],
    control: &OperationControl,
    progress: &mut dyn FnMut(OperationProgress),
) -> Result<(), OperationError<BackupError>> {
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let backup_path = backup_path.as_ref();
    progress(OperationProgress::phase(OperationPhase::Preparing));
    let rng = OsRandomSource::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt).map_err(BackupError::from)?;
    let mut nonce = [0u8; BODY_NONCE_LEN];
    rng.fill_bytes(&mut nonce).map_err(BackupError::from)?;
    progress(OperationProgress::phase(OperationPhase::Processing));
    let params = KdfParams::v1_default();
    let backup_kek = derive_backup_kek(backup_passphrase, &salt, &params)?;
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let header = build_header(params, salt.to_vec(), backup_kek.as_ref())?;
    let backup_body = session
        .clone_body_rewrapped(backup_kek.as_ref())
        .map_err(BackupError::from)?;
    let body_bytes =
        Zeroizing::new(serde_helpers::to_vec(&backup_body).map_err(BackupError::from)?);
    let header_bytes = serde_helpers::to_vec(&header).map_err(BackupError::from)?;
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let ciphertext = aead::encrypt(
        AeadAlgorithm::Aes256Gcm,
        backup_kek.as_ref(),
        &nonce,
        &header_bytes,
        &body_bytes,
    )
    .map_err(BackupError::from)?;
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let total =
        (MAGIC.len() + HEADER_LEN_PREFIX + header_bytes.len() + nonce.len() + ciphertext.len())
            as u64;
    progress(OperationProgress::measured(
        OperationPhase::WritingOutput,
        0,
        total,
    ));
    write_backup_file_controlled(backup_path, &header_bytes, &nonce, &ciphertext, control)?;
    progress(OperationProgress::measured(
        OperationPhase::WritingOutput,
        total,
        total,
    ));
    progress(OperationProgress::phase(OperationPhase::Completed));
    Ok(())
}

fn write_backup_file_controlled(
    path: &Path,
    header_bytes: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    control: &OperationControl,
) -> Result<(), OperationError<BackupError>> {
    let header_len =
        u32::try_from(header_bytes.len()).map_err(|_| BackupError::Corrupt("header too large"))?;
    let mut out = Vec::with_capacity(
        MAGIC.len() + HEADER_LEN_PREFIX + header_bytes.len() + nonce.len() + ciphertext.len(),
    );
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&header_len.to_be_bytes());
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let (tmp, mut file) = create_unique_temp_file(path)?;
    let mut published = false;
    let result = (|| -> Result<(), OperationError<BackupError>> {
        file.write_all(&out).map_err(BackupError::from)?;
        file.sync_all().map_err(BackupError::from)?;
        drop(file);
        control
            .check_cancelled()
            .map_err(OperationError::Cancelled)?;
        fs::hard_link(&tmp, path).map_err(BackupError::from)?;
        published = true;
        fs::remove_file(&tmp).map_err(BackupError::from)?;
        restrict_file_permissions(path)?;
        sync_parent_dir(path)?;
        Ok(())
    })();
    if result.is_err() {
        let mut cleanup_errors = Vec::new();
        if published
            && let Err(error) = fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            cleanup_errors.push(error.to_string());
        }
        if let Err(error) = fs::remove_file(&tmp)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            cleanup_errors.push(error.to_string());
        }
        if !cleanup_errors.is_empty() {
            return Err(BackupError::Io(std::io::Error::other(format!(
                "backup operation failed and partial-output cleanup failed: {}",
                cleanup_errors.join("; ")
            )))
            .into());
        }
    } else {
        let _ = fs::remove_file(&tmp);
    }
    result
}

// =============================================================================
// Import
// =============================================================================

/// Imports a backup into a new vault.
///
/// The new vault is created with `new_vault_password` at
/// `new_vault_path`. Its content is the one captured in the backup,
/// re-wrapped under a fresh KEK derived from the new password.
///
/// # Errors
///
/// Returns [`BackupError::WrongPassphrase`] if the backup passphrase
/// is incorrect, [`BackupError::Io`] if either file cannot be read or
/// written, or another backup error if parsing or cryptography fails.
pub fn import(
    backup_path: impl AsRef<Path>,
    backup_passphrase: &[u8],
    new_vault_path: impl AsRef<Path>,
    new_vault_password: &[u8],
) -> Result<Vault, BackupError> {
    let backup_path = backup_path.as_ref();
    let new_vault_path = new_vault_path.as_ref();

    let bytes = fs::read(backup_path)?;
    let (header, rest) = parse_backup_file(&bytes)?;

    if rest.len() < BODY_NONCE_LEN + aead::TAG_LEN {
        return Err(BackupError::Corrupt("body is truncated"));
    }
    let (nonce, ciphertext) = rest.split_at(BODY_NONCE_LEN);

    let backup_kek = derive_backup_kek(backup_passphrase, &header.salt, &header.kdf)?;
    verify_backup_kek(&header, backup_kek.as_ref())?;

    let header_bytes = serde_helpers::to_vec(&header)?;
    let plaintext = Zeroizing::new(
        aead::decrypt(
            AeadAlgorithm::Aes256Gcm,
            backup_kek.as_ref(),
            nonce,
            &header_bytes,
            ciphertext,
        )
        .map_err(|_| BackupError::WrongPassphrase)?,
    );

    let mut body: VaultBody = serde_helpers::from_slice(plaintext.as_ref())?;

    // Audit logs are external to the backup bundle and are authenticated
    // with the source vault's KEK. A restored vault gets a new KEK, so
    // carrying the source audit path forward would make unlock fail
    // against an unrelated log. Require the restored vault to explicitly
    // attach a new audit log instead.
    body.audit_dir = None;
    body.audit_anchor = None;

    // Create a fresh vault and replace its body with the imported one.
    Vault::create(new_vault_path, new_vault_password, None)?;
    let vault = Vault::open(new_vault_path)?;
    let mut session = vault.unlock(new_vault_password)?;
    session.rewrap_body_from(&mut body, backup_kek.as_ref())?;
    *session.body_mut()? = body;
    let vault = session.lock()?;

    Ok(vault)
}

/// Import a backup with safe cancellation points and backend progress updates.
/// Once destination creation starts, the operation completes or removes the
/// newly-created vault file; cancellation is not reported mid-commit.
pub fn import_controlled(
    backup_path: impl AsRef<Path>,
    backup_passphrase: &[u8],
    new_vault_path: impl AsRef<Path>,
    new_vault_password: &[u8],
    control: &OperationControl,
    progress: &mut dyn FnMut(OperationProgress),
) -> Result<Vault, OperationError<BackupError>> {
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let backup_path = backup_path.as_ref();
    let new_vault_path = new_vault_path.as_ref();
    let total = fs::metadata(backup_path).map_err(BackupError::from)?.len();
    progress(OperationProgress::measured(
        OperationPhase::ReadingInput,
        0,
        total,
    ));
    let bytes = fs::read(backup_path).map_err(BackupError::from)?;
    if bytes.len() as u64 != total {
        return Err(BackupError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "backup changed while it was being read",
        ))
        .into());
    }
    progress(OperationProgress::measured(
        OperationPhase::ReadingInput,
        bytes.len() as u64,
        total,
    ));
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let (header, rest) = parse_backup_file(&bytes)?;
    if rest.len() < BODY_NONCE_LEN + aead::TAG_LEN {
        return Err(BackupError::Corrupt("body is truncated").into());
    }
    let (nonce, ciphertext) = rest.split_at(BODY_NONCE_LEN);
    progress(OperationProgress::phase(OperationPhase::Processing));
    let backup_kek = derive_backup_kek(backup_passphrase, &header.salt, &header.kdf)?;
    verify_backup_kek(&header, backup_kek.as_ref())?;
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let header_bytes = serde_helpers::to_vec(&header).map_err(BackupError::from)?;
    let plaintext = Zeroizing::new(
        aead::decrypt(
            AeadAlgorithm::Aes256Gcm,
            backup_kek.as_ref(),
            nonce,
            &header_bytes,
            ciphertext,
        )
        .map_err(|_| BackupError::WrongPassphrase)?,
    );
    let mut body: VaultBody =
        serde_helpers::from_slice(plaintext.as_ref()).map_err(BackupError::from)?;
    body.audit_dir = None;
    body.audit_anchor = None;
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    progress(OperationProgress::phase(OperationPhase::Verifying));
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    progress(OperationProgress::phase(OperationPhase::WritingOutput));
    Vault::create(new_vault_path, new_vault_password, None).map_err(BackupError::from)?;
    let result = (|| -> Result<Vault, BackupError> {
        let vault = Vault::open(new_vault_path)?;
        let mut session = vault.unlock(new_vault_password)?;
        session.rewrap_body_from(&mut body, backup_kek.as_ref())?;
        *session.body_mut()? = body;
        Ok(session.lock()?)
    })();
    match result {
        Ok(vault) => {
            progress(OperationProgress::phase(OperationPhase::Completed));
            Ok(vault)
        }
        Err(error) => match fs::remove_file(new_vault_path) {
            Ok(()) => Err(error.into()),
            Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => Err(error.into()),
            Err(cleanup) => Err(BackupError::Io(std::io::Error::other(format!(
                "{error}; newly-created vault cleanup failed: {cleanup}"
            )))
            .into()),
        },
    }
}

// =============================================================================
// Header helpers
// =============================================================================

fn build_header(kdf: KdfParams, salt: Vec<u8>, kek: &[u8]) -> Result<BackupHeader, BackupError> {
    if salt.len() != SALT_LEN {
        return Err(BackupError::Corrupt("invalid salt length"));
    }
    let verifier = compute_kek_verifier(kek)?;
    Ok(BackupHeader {
        magic: MAGIC,
        version: FORMAT_VERSION,
        flags: 0,
        kdf,
        salt,
        kek_verifier: verifier,
    })
}

fn verify_backup_kek(header: &BackupHeader, kek: &[u8]) -> Result<(), BackupError> {
    let computed = compute_kek_verifier(kek)?;
    if computed == header.kek_verifier {
        Ok(())
    } else {
        Err(BackupError::WrongPassphrase)
    }
}

fn compute_kek_verifier(kek: &[u8]) -> Result<[u8; KEK_VERIFIER_LEN], BackupError> {
    let mut verifier = [0u8; KEK_VERIFIER_LEN];
    let derived =
        kdf::hkdf_sha256(kek, None, BACKUP_KEK_VERIFIER_INFO).map_err(BackupError::Kdf)?;
    verifier.copy_from_slice(&*derived);
    Ok(verifier)
}

fn derive_backup_kek(
    passphrase: &[u8],
    salt: &[u8],
    _params: &KdfParams,
) -> Result<Zeroizing<[u8; kdf::DERIVED_KEY_LEN]>, BackupError> {
    // Only Argon2id is supported in v1; the params field is present
    // for future algorithm agility, the same way it is in the vault.
    Ok(kdf::argon2id(passphrase, salt)?)
}

// =============================================================================
// File I/O
// =============================================================================

fn write_backup_file(
    path: &Path,
    header_bytes: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), BackupError> {
    let header_len =
        u32::try_from(header_bytes.len()).map_err(|_| BackupError::Corrupt("header too large"))?;

    let mut out = Vec::with_capacity(
        MAGIC.len() + HEADER_LEN_PREFIX + header_bytes.len() + nonce.len() + ciphertext.len(),
    );
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&header_len.to_be_bytes());
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);

    let (tmp, mut file) = create_unique_temp_file(path)?;
    file.write_all(&out)?;
    file.sync_all()?;
    drop(file);
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(BackupError::Io(e));
    }
    restrict_file_permissions(path)?;
    sync_parent_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

fn parse_backup_file(bytes: &[u8]) -> Result<(BackupHeader, &[u8]), BackupError> {
    if bytes.len() < MAGIC.len() + HEADER_LEN_PREFIX {
        return Err(BackupError::Corrupt("file too small"));
    }
    let (magic, rest) = bytes.split_at(MAGIC.len());
    if magic != MAGIC {
        return Err(BackupError::BadMagic);
    }

    let (len_bytes, rest) = rest.split_at(HEADER_LEN_PREFIX);
    let header_len = u32::from_be_bytes(len_bytes.try_into().expect("4 bytes")) as usize;

    if rest.len() < header_len {
        return Err(BackupError::Corrupt("header length exceeds file size"));
    }
    let (header_bytes, rest) = rest.split_at(header_len);

    let header: BackupHeader = serde_helpers::from_slice(header_bytes)?;
    if !header.is_supported() {
        return Err(BackupError::UnsupportedVersion(header.version));
    }

    Ok((header, rest))
}

fn create_unique_temp_file(path: &Path) -> Result<(PathBuf, fs::File), BackupError> {
    for _ in 0..16 {
        let mut suffix = [0u8; 16];
        getrandom::fill(&mut suffix)
            .map_err(|e| BackupError::Io(std::io::Error::other(e.to_string())))?;
        let name = format!(
            "{}.tmp-{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("backup"),
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
            Err(err) => return Err(BackupError::Io(err)),
        }
    }
    Err(BackupError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate unique backup temp file",
    )))
}

fn sync_parent_dir(path: &Path) -> Result<(), BackupError> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

// KdfAlgorithm is re-exported by the vault header module and used
// implicitly through KdfParams; keep the import exercised.
#[allow(dead_code)]
fn _keep_kdf_algorithm_in_scope(_a: KdfAlgorithm) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Algorithm;
    use crate::vault::Purpose;
    use tempfile::TempDir;

    fn create_vault_with_key(dir: &TempDir, name: &str) -> (PathBuf, Vec<u8>) {
        let path = dir.path().join(name);
        let password = b"vault-password".to_vec();
        Vault::create(&path, &password, Some("test".to_string())).unwrap();

        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(&password).unwrap();
        let id = session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();
        session.activate_key(&id).unwrap();
        session.lock().unwrap();

        (path, password)
    }

    #[test]
    fn export_then_import_roundtrip() {
        let dir = TempDir::new().unwrap();
        let (vault_path, vault_pw) = create_vault_with_key(&dir, "original.nqv");
        let backup_path = dir.path().join("backup.nqb");
        let new_vault_path = dir.path().join("restored.nqv");

        let backup_pw = b"backup-passphrase";
        let new_pw = b"new-vault-password";

        // Export.
        {
            let vault = Vault::open(&vault_path).unwrap();
            let session = vault.unlock(&vault_pw).unwrap();
            export(&session, &backup_path, backup_pw).unwrap();
            assert!(backup_path.exists());
        }

        // Import.
        let vault = import(&backup_path, backup_pw, &new_vault_path, new_pw).unwrap();
        assert_eq!(vault.path(), new_vault_path.as_path());

        // The restored vault opens with the NEW password and has the
        // same content.
        let vault = Vault::open(&new_vault_path).unwrap();
        let session = vault.unlock(new_pw).unwrap();
        assert_eq!(session.key_count(), 1);
    }

    #[test]
    fn controlled_backup_roundtrip_emits_truthful_progress() {
        let dir = TempDir::new().unwrap();
        let (vault_path, vault_pw) = create_vault_with_key(&dir, "controlled-source.nqv");
        let backup_path = dir.path().join("controlled.nqb");
        let restored_path = dir.path().join("controlled-restored.nqv");
        let mut updates = Vec::new();
        {
            let session = Vault::open(&vault_path).unwrap().unlock(&vault_pw).unwrap();
            let mut reporter = |progress| updates.push(progress);
            export_controlled(
                &session,
                &backup_path,
                b"separate-backup-passphrase",
                &OperationControl::new(),
                &mut reporter,
            )
            .unwrap();
        }
        assert!(
            updates
                .iter()
                .any(|item| item.phase == OperationPhase::WritingOutput
                    && item.completed == Some(0)
                    && item.total.is_some())
        );
        assert_eq!(updates.first().unwrap().phase, OperationPhase::Preparing);
        assert_eq!(updates.last().unwrap().phase, OperationPhase::Completed);
        let processing_index = updates
            .iter()
            .position(|item| item.phase == OperationPhase::Processing)
            .unwrap();
        let writing_index = updates
            .iter()
            .position(|item| item.phase == OperationPhase::WritingOutput)
            .unwrap();
        assert!(processing_index < writing_index);
        let mut import_updates = Vec::new();
        let mut reporter = |progress| import_updates.push(progress);
        import_controlled(
            &backup_path,
            b"separate-backup-passphrase",
            &restored_path,
            b"new-vault-password",
            &OperationControl::new(),
            &mut reporter,
        )
        .unwrap();
        assert!(
            import_updates
                .iter()
                .any(|item| item.phase == OperationPhase::ReadingInput
                    && item.completed == item.total)
        );
        assert_eq!(
            import_updates.first().unwrap().phase,
            OperationPhase::ReadingInput
        );
        assert_eq!(
            import_updates.last().unwrap().phase,
            OperationPhase::Completed
        );
        let verifying_index = import_updates
            .iter()
            .position(|item| item.phase == OperationPhase::Verifying)
            .unwrap();
        let writing_index = import_updates
            .iter()
            .position(|item| item.phase == OperationPhase::WritingOutput)
            .unwrap();
        assert!(verifying_index < writing_index);
        let restored = Vault::open(&restored_path)
            .unwrap()
            .unlock(b"new-vault-password")
            .unwrap();
        assert_eq!(restored.key_count(), 1);
    }

    #[test]
    fn controlled_backup_import_cancellation_does_not_create_destination_vault() {
        let dir = TempDir::new().unwrap();
        let (vault_path, vault_pw) = create_vault_with_key(&dir, "cancel-import-source.nqv");
        let backup_path = dir.path().join("cancel-import.nqb");
        let restored_path = dir.path().join("cancel-import-restored.nqv");
        {
            let session = Vault::open(&vault_path).unwrap().unlock(&vault_pw).unwrap();
            export(&session, &backup_path, b"separate-backup-passphrase").unwrap();
        }
        let control = OperationControl::new();
        control.cancel();
        let result = import_controlled(
            &backup_path,
            b"separate-backup-passphrase",
            &restored_path,
            b"new-vault-password",
            &control,
            &mut |_| {},
        );
        assert!(matches!(result, Err(OperationError::Cancelled(_))));
        assert!(!restored_path.exists());
    }

    #[test]
    fn controlled_backup_export_never_replaces_existing_destination() {
        let dir = TempDir::new().unwrap();
        let (vault_path, vault_pw) = create_vault_with_key(&dir, "existing-backup-source.nqv");
        let backup_path = dir.path().join("existing.nqb");
        fs::write(&backup_path, b"original backup bytes").unwrap();
        let session = Vault::open(&vault_path).unwrap().unlock(&vault_pw).unwrap();
        let result = export_controlled(
            &session,
            &backup_path,
            b"separate-backup-passphrase",
            &OperationControl::new(),
            &mut |_| {},
        );
        assert!(
            matches!(result, Err(OperationError::Failed(BackupError::Io(error))) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&backup_path).unwrap(), b"original backup bytes");
        assert_eq!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .contains("existing.nqb.tmp-"))
                .count(),
            0
        );
    }

    #[test]
    fn controlled_backup_cancellation_does_not_publish_output() {
        let dir = TempDir::new().unwrap();
        let (vault_path, vault_pw) = create_vault_with_key(&dir, "cancel-source.nqv");
        let backup_path = dir.path().join("cancelled.nqb");
        let session = Vault::open(&vault_path).unwrap().unlock(&vault_pw).unwrap();
        let control = OperationControl::new();
        control.cancel();
        let result = export_controlled(
            &session,
            &backup_path,
            b"separate-backup-passphrase",
            &control,
            &mut |_| {},
        );
        assert!(matches!(result, Err(OperationError::Cancelled(_))));
        assert!(!backup_path.exists());
    }

    #[test]
    fn import_rejects_wrong_backup_passphrase() {
        let dir = TempDir::new().unwrap();
        let (vault_path, vault_pw) = create_vault_with_key(&dir, "v.nqv");
        let backup_path = dir.path().join("b.nqb");
        let new_vault_path = dir.path().join("n.nqv");

        {
            let vault = Vault::open(&vault_path).unwrap();
            let session = vault.unlock(&vault_pw).unwrap();
            export(&session, &backup_path, b"correct").unwrap();
        }

        let err = import(&backup_path, b"wrong", &new_vault_path, b"pw").unwrap_err();
        assert!(matches!(err, BackupError::WrongPassphrase));
    }

    #[test]
    fn import_rejects_vault_password_as_backup_passphrase() {
        let dir = TempDir::new().unwrap();
        let (vault_path, vault_pw) = create_vault_with_key(&dir, "v.nqv");
        let backup_path = dir.path().join("b.nqb");
        let new_vault_path = dir.path().join("n.nqv");

        {
            let vault = Vault::open(&vault_path).unwrap();
            let session = vault.unlock(&vault_pw).unwrap();
            export(&session, &backup_path, b"backup-pw").unwrap();
        }

        // The vault password is not the backup passphrase.
        let err = import(&backup_path, &vault_pw, &new_vault_path, b"pw").unwrap_err();
        assert!(matches!(err, BackupError::WrongPassphrase));
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let bytes = b"XXXX\x00\x00\x00\x00";
        assert!(matches!(
            parse_backup_file(bytes),
            Err(BackupError::BadMagic)
        ));
    }

    #[test]
    fn parse_rejects_truncated_file() {
        let bytes = b"NQ";
        assert!(matches!(
            parse_backup_file(bytes),
            Err(BackupError::Corrupt(_))
        ));
    }

    #[test]
    fn tampering_with_header_breaks_decryption() {
        let dir = TempDir::new().unwrap();
        let (vault_path, vault_pw) = create_vault_with_key(&dir, "v.nqv");
        let backup_path = dir.path().join("b.nqb");
        let new_vault_path = dir.path().join("n.nqv");

        {
            let vault = Vault::open(&vault_path).unwrap();
            let session = vault.unlock(&vault_pw).unwrap();
            export(&session, &backup_path, b"pw").unwrap();
        }

        let mut bytes = fs::read(&backup_path).unwrap();
        // Flip a byte somewhere in the header region.
        let header_start = MAGIC.len() + HEADER_LEN_PREFIX;
        bytes[header_start] ^= 0x01;
        fs::write(&backup_path, &bytes).unwrap();

        let err = import(&backup_path, b"pw", &new_vault_path, b"new").unwrap_err();
        assert!(matches!(
            err,
            BackupError::WrongPassphrase | BackupError::Cbor(_)
        ));
    }

    #[test]
    fn restored_vault_id_is_preserved() {
        let dir = TempDir::new().unwrap();
        let (vault_path, vault_pw) = create_vault_with_key(&dir, "v.nqv");
        let backup_path = dir.path().join("b.nqb");
        let new_vault_path = dir.path().join("n.nqv");

        let original_id = {
            let vault = Vault::open(&vault_path).unwrap();
            let session = vault.unlock(&vault_pw).unwrap();
            export(&session, &backup_path, b"pw").unwrap();
            session.body().metadata.vault_id.clone()
        };

        import(&backup_path, b"pw", &new_vault_path, b"new").unwrap();
        let vault = Vault::open(&new_vault_path).unwrap();
        let session = vault.unlock(b"new").unwrap();
        assert_eq!(session.body().metadata.vault_id, original_id);
    }
}

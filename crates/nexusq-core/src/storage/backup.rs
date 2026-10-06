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
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::aead::{self, AeadError, Algorithm as AeadAlgorithm};
use crate::crypto::kdf::{self, KdfError};
use crate::crypto::random::{OsRandomSource, RandomError, RandomSource};
use crate::vault::body::VaultBody;
use crate::vault::header::{HeaderError, KdfAlgorithm, KdfParams};
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
    let body_bytes = serde_helpers::to_vec(&backup_body)?;
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
    let plaintext = aead::decrypt(
        AeadAlgorithm::Aes256Gcm,
        backup_kek.as_ref(),
        nonce,
        &header_bytes,
        ciphertext,
    )
    .map_err(|_| BackupError::WrongPassphrase)?;

    let mut body: VaultBody = serde_helpers::from_slice(&plaintext)?;

    // Audit logs are external to the backup bundle and are authenticated
    // with the source vault's KEK. A restored vault gets a new KEK, so
    // carrying the source audit path forward would make unlock fail
    // against an unrelated log. Require the restored vault to explicitly
    // attach a new audit log instead.
    body.audit_dir = None;

    // Create a fresh vault and replace its body with the imported one.
    Vault::create(new_vault_path, new_vault_password, None)?;
    let vault = Vault::open(new_vault_path)?;
    let mut session = vault.unlock(new_vault_password)?;
    session.rewrap_body_from(&mut body, backup_kek.as_ref())?;
    *session.body_mut()? = body;
    let vault = session.lock()?;

    Ok(vault)
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

    let tmp = temp_path(path);
    fs::write(&tmp, &out)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(BackupError::Io(e));
    }
    restrict_file_permissions(path)?;
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

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
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

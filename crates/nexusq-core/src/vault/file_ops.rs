//! File-level operations on envelopes.
//!
//! Thin wrappers that read a plaintext file, build an envelope, and
//! write the result to a `.nqx` file — or the reverse.
//!
//! ## Naming convention
//!
//! Encrypted files use the extension `.nqx`:
//!
//! ```text
//! document.pdf  ->  document.pdf.nqx
//! ```
//!
//! `encrypt_*_to_path` adds the suffix if it is not already present.
//! `decrypt_*_to_path` takes an explicit output path; the caller
//! decides where the plaintext lands.
//!
//! ## In-memory processing
//!
//! For v1.0, files are read entirely into memory. This matches ADR
//! 0003's constraint that envelopes are for files that fit comfortably
//! in memory. Streaming envelopes land in a later phase.
//!
//! ## Output safety
//!
//! File operations publish output without replacing an existing path:
//! bytes are written to an exclusive temporary file in the destination
//! directory, synced, and hard-linked into place. This prevents readers
//! from observing partial output and avoids clobbering an existing file.
//! Input and envelope bytes are still processed entirely in memory.

use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::envelope::{self, EnvelopeError};
use super::key_id::KeyId;
use super::operation::{OperationControl, OperationError, OperationPhase, OperationProgress};
use super::record::KeyRecord;

/// File extension used for encrypted files.
pub const ENCRYPTED_EXTENSION: &str = "nqx";

/// Builds the `.nqx` path for a given plaintext path.
///
/// If the input already ends with `.nqx`, it is returned unchanged.
#[must_use]
pub fn encrypted_path_for(input: &Path) -> PathBuf {
    let ext = input.extension().and_then(|e| e.to_str());
    if ext == Some(ENCRYPTED_EXTENSION) {
        return input.to_path_buf();
    }
    let mut name = input.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(ENCRYPTED_EXTENSION);
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    parent.join(name)
}

/// Encrypts a file to the recipient's public key.
///
/// Reads `input`, builds a public-key envelope, and writes the result
/// next to the input with a `.nqx` extension. Returns the path of the
/// encrypted file.
///
/// # Errors
///
/// Returns [`EnvelopeError::Io`] if either file cannot be read or
/// written, or another envelope error if construction fails.
pub fn encrypt_file_to_public_key(
    input: impl AsRef<Path>,
    recipient_public_key: &[u8],
    metadata: Vec<u8>,
) -> Result<PathBuf, EnvelopeError> {
    let input = input.as_ref();
    let plaintext = fs::read(input)?;
    let envelope_bytes =
        envelope::build_envelope_to_public_key(recipient_public_key, &plaintext, metadata)?;
    let output = encrypted_path_for(input);
    write_new_atomic(&output, &envelope_bytes)?;
    Ok(output)
}

/// Opens a public-key envelope file and writes the plaintext to
/// `output`.
///
/// # Errors
///
/// Returns [`EnvelopeError::Io`] if either file cannot be read or
/// written, or another envelope error if decryption fails.
pub fn decrypt_file_with_kem(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    key_pair: &crate::crypto::kem::hybrid::KeyPair,
) -> Result<(), EnvelopeError> {
    let envelope_bytes = fs::read(input.as_ref())?;
    let plaintext = envelope::open_envelope_with_kem(key_pair, &envelope_bytes)?;
    write_zeroizing(output.as_ref(), &plaintext)?;
    Ok(())
}

/// Encrypts a file under a vault key, using the given `kek`.
///
/// This is the low-level worker called by
/// [`Session::encrypt_file`](super::Session::encrypt_file). It takes
/// the KEK directly so the caller controls where it comes from.
///
/// # Errors
///
/// Returns [`EnvelopeError::Io`] if either file cannot be read or
/// written, or another envelope error if construction fails.
pub fn encrypt_file_with_key(
    input: impl AsRef<Path>,
    kek: &[u8],
    key_record: &KeyRecord,
    metadata: Vec<u8>,
) -> Result<PathBuf, EnvelopeError> {
    let input = input.as_ref();
    let plaintext = fs::read(input)?;
    let envelope_bytes = envelope::build_envelope(kek, key_record, &plaintext, metadata)?;
    let output = encrypted_path_for(input);
    write_new_atomic(&output, &envelope_bytes)?;
    Ok(output)
}

/// Opens a vault-mode envelope file and writes the plaintext to
/// `output`.
///
/// # Errors
///
/// Returns [`EnvelopeError::Io`] if either file cannot be read or
/// written, [`EnvelopeError::KeyNotFound`] if `lookup` returns `None`
/// for the envelope's KeyId, or another envelope error if decryption
/// fails.
pub fn decrypt_file_with_key<F>(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    kek: &[u8],
    lookup: F,
) -> Result<(), EnvelopeError>
where
    F: FnOnce(&KeyId) -> Option<KeyRecord>,
{
    let envelope_bytes = fs::read(input.as_ref())?;
    let plaintext = envelope::open_envelope(kek, &envelope_bytes, lookup)?;
    write_zeroizing(output.as_ref(), &plaintext)?;
    Ok(())
}

/// Controlled variant of [`encrypt_file_with_key`]. Cancellation is observed
/// after the complete input read, after encryption, and before publishing the
/// output. The existing destination is never replaced.
pub fn encrypt_file_with_key_controlled(
    input: impl AsRef<Path>,
    kek: &[u8],
    key_record: &KeyRecord,
    metadata: Vec<u8>,
    control: &OperationControl,
    progress: &mut dyn FnMut(OperationProgress),
) -> Result<PathBuf, OperationError<EnvelopeError>> {
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let input = input.as_ref();
    let total = fs::metadata(input).map_err(EnvelopeError::Io)?.len();
    progress(OperationProgress::measured(
        OperationPhase::ReadingInput,
        0,
        total,
    ));
    let plaintext = Zeroizing::new(fs::read(input).map_err(EnvelopeError::Io)?);
    if plaintext.len() as u64 != total {
        return Err(EnvelopeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "input file changed while it was being read",
        ))
        .into());
    }
    progress(OperationProgress::measured(
        OperationPhase::ReadingInput,
        plaintext.len() as u64,
        total,
    ));
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    progress(OperationProgress::phase(OperationPhase::Processing));
    let envelope_bytes = envelope::build_envelope(kek, key_record, &plaintext, metadata)?;
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let output = encrypted_path_for(input);
    progress(OperationProgress::measured(
        OperationPhase::WritingOutput,
        0,
        envelope_bytes.len() as u64,
    ));
    write_new_atomic_controlled(&output, &envelope_bytes, control)?;
    progress(OperationProgress::measured(
        OperationPhase::WritingOutput,
        envelope_bytes.len() as u64,
        envelope_bytes.len() as u64,
    ));
    Ok(output)
}

/// Controlled variant of [`decrypt_file_with_key`]. Decrypted plaintext is
/// held in zeroizing memory and is not published if cancellation is observed.
pub fn decrypt_file_with_key_controlled<F>(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    kek: &[u8],
    lookup: F,
    control: &OperationControl,
    progress: &mut dyn FnMut(OperationProgress),
) -> Result<(), OperationError<EnvelopeError>>
where
    F: FnOnce(&KeyId) -> Option<KeyRecord>,
{
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let input = input.as_ref();
    let total = fs::metadata(input).map_err(EnvelopeError::Io)?.len();
    progress(OperationProgress::measured(
        OperationPhase::ReadingInput,
        0,
        total,
    ));
    let envelope_bytes = fs::read(input).map_err(EnvelopeError::Io)?;
    if envelope_bytes.len() as u64 != total {
        return Err(EnvelopeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted input changed while it was being read",
        ))
        .into());
    }
    progress(OperationProgress::measured(
        OperationPhase::ReadingInput,
        envelope_bytes.len() as u64,
        total,
    ));
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    progress(OperationProgress::phase(OperationPhase::Processing));
    let plaintext = envelope::open_envelope(kek, &envelope_bytes, lookup)?;
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    progress(OperationProgress::measured(
        OperationPhase::WritingOutput,
        0,
        plaintext.len() as u64,
    ));
    write_new_atomic_controlled(output.as_ref(), plaintext.as_slice(), control)?;
    progress(OperationProgress::measured(
        OperationPhase::WritingOutput,
        plaintext.len() as u64,
        plaintext.len() as u64,
    ));
    Ok(())
}

fn write_new_atomic_controlled(
    path: &Path,
    data: &[u8],
    control: &OperationControl,
) -> Result<(), OperationError<EnvelopeError>> {
    control
        .check_cancelled()
        .map_err(OperationError::Cancelled)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path.file_name().unwrap_or_default();
    let (temp_path, mut file) =
        create_unique_temp_file(parent, file_name).map_err(EnvelopeError::Io)?;
    let mut published = false;
    let result = (|| -> Result<(), OperationError<EnvelopeError>> {
        use std::io::Write;
        file.write_all(data).map_err(EnvelopeError::Io)?;
        file.sync_all().map_err(EnvelopeError::Io)?;
        drop(file);
        control
            .check_cancelled()
            .map_err(OperationError::Cancelled)?;
        fs::hard_link(&temp_path, path).map_err(EnvelopeError::Io)?;
        published = true;
        fs::remove_file(&temp_path).map_err(EnvelopeError::Io)?;
        #[cfg(unix)]
        {
            let dir = fs::File::open(parent).map_err(EnvelopeError::Io)?;
            match dir.sync_all() {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {}
                Err(error) => return Err(EnvelopeError::Io(error).into()),
            }
        }
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
        if let Err(error) = fs::remove_file(&temp_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            cleanup_errors.push(error.to_string());
        }
        if !cleanup_errors.is_empty() {
            return Err(EnvelopeError::Io(std::io::Error::other(format!(
                "operation failed and partial-output cleanup failed: {}",
                cleanup_errors.join("; ")
            )))
            .into());
        }
    } else {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

/// Writes plaintext without replacing an existing destination.
fn write_zeroizing(path: &Path, data: &Zeroizing<Vec<u8>>) -> std::io::Result<()> {
    write_new_atomic(path, data.as_slice())
}

/// Publishes a complete file atomically and only if `path` does not exist.
/// The temporary file is created in the same directory so hard-link
/// publication cannot cross filesystems. A hard link, unlike rename,
/// fails rather than replacing a destination created by a racing process.
fn write_new_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path.file_name().unwrap_or_default();
    let (temp_path, mut file) = create_unique_temp_file(parent, file_name)?;

    let result = (|| {
        use std::io::Write;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temp_path, path)?;
        fs::remove_file(&temp_path)?;
        #[cfg(unix)]
        {
            let dir = fs::File::open(parent)?;
            match dir.sync_all() {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })();
    let _ = fs::remove_file(&temp_path);
    result
}

fn create_unique_temp_file(
    parent: &Path,
    file_name: &std::ffi::OsStr,
) -> std::io::Result<(PathBuf, fs::File)> {
    for _ in 0..16 {
        let mut suffix = [0u8; 16];
        getrandom::fill(&mut suffix).map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut name = file_name.to_os_string();
        name.push(format!(".tmp-{}", hex::encode(suffix)));
        let temp_path = parent.join(name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate unique file temp",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn atomic_writer_does_not_overwrite_existing_destination() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("existing.bin");
        fs::write(&destination, b"original").unwrap();

        let error = write_new_atomic(&destination, b"replacement").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn atomic_writer_publishes_complete_file_with_private_permissions() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("new.bin");
        write_new_atomic(&destination, b"complete payload").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"complete payload");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(destination).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn controlled_session_file_roundtrip_reports_backend_phases() {
        use crate::vault::{Algorithm, Purpose, Vault};
        let dir = TempDir::new().unwrap();
        let password = b"controlled-file-vault-password";
        let vault =
            Vault::create(dir.path().join("controlled-roundtrip.nqv"), password, None).unwrap();
        let mut session = vault.unlock(password).unwrap();
        let key_id = session
            .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
            .unwrap();
        session.activate_key(&key_id).unwrap();
        let input = dir.path().join("roundtrip.txt");
        fs::write(&input, b"controlled file roundtrip").unwrap();
        let mut encrypt_updates = Vec::new();
        let mut reporter = |update| encrypt_updates.push(update);
        let encrypted = session
            .encrypt_file_controlled(
                &input,
                &key_id,
                Vec::new(),
                &OperationControl::new(),
                &mut reporter,
            )
            .unwrap();
        assert!(encrypted.exists());
        assert_eq!(fs::read(&input).unwrap(), b"controlled file roundtrip");
        assert_eq!(
            encrypt_updates.last().unwrap().phase,
            OperationPhase::Completed
        );
        let encrypt_phases: Vec<_> = encrypt_updates.iter().map(|item| item.phase).collect();
        let read = encrypt_phases
            .iter()
            .position(|phase| *phase == OperationPhase::ReadingInput)
            .unwrap();
        let process = encrypt_phases
            .iter()
            .position(|phase| *phase == OperationPhase::Processing)
            .unwrap();
        let write = encrypt_phases
            .iter()
            .position(|phase| *phase == OperationPhase::WritingOutput)
            .unwrap();
        let completed = encrypt_phases
            .iter()
            .position(|phase| *phase == OperationPhase::Completed)
            .unwrap();
        assert!(read < process && process < write && write < completed);
        assert!(encrypt_updates.iter().any(|item| {
            item.phase == OperationPhase::ReadingInput
                && item.completed == item.total
                && item.total == Some(b"controlled file roundtrip".len() as u64)
        }));
        let output = dir.path().join("roundtrip-restored.txt");
        let mut decrypt_updates = Vec::new();
        let mut reporter = |update| decrypt_updates.push(update);
        session
            .decrypt_file_controlled(&encrypted, &output, &OperationControl::new(), &mut reporter)
            .unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"controlled file roundtrip");
        assert_eq!(
            decrypt_updates.last().unwrap().phase,
            OperationPhase::Completed
        );
        let decrypt_phases: Vec<_> = decrypt_updates.iter().map(|item| item.phase).collect();
        let read = decrypt_phases
            .iter()
            .position(|phase| *phase == OperationPhase::ReadingInput)
            .unwrap();
        let process = decrypt_phases
            .iter()
            .position(|phase| *phase == OperationPhase::Processing)
            .unwrap();
        let write = decrypt_phases
            .iter()
            .position(|phase| *phase == OperationPhase::WritingOutput)
            .unwrap();
        let completed = decrypt_phases
            .iter()
            .position(|phase| *phase == OperationPhase::Completed)
            .unwrap();
        assert!(read < process && process < write && write < completed);
    }

    #[test]
    fn controlled_session_encrypt_cancellation_after_read_keeps_original_and_publishes_nothing() {
        use crate::vault::{Algorithm, Purpose, Vault};
        let dir = TempDir::new().unwrap();
        let password = b"controlled-file-vault-password";
        let vault = Vault::create(dir.path().join("controlled.nqv"), password, None).unwrap();
        let mut session = vault.unlock(password).unwrap();
        let key_id = session
            .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
            .unwrap();
        session.activate_key(&key_id).unwrap();
        let input = dir.path().join("source.txt");
        fs::write(&input, b"keep the original file").unwrap();
        let output = encrypted_path_for(&input);
        let control = OperationControl::new();
        let mut reporter = |update: OperationProgress| {
            if update.phase == OperationPhase::ReadingInput && update.completed == update.total {
                control.cancel();
            }
        };
        let result =
            session.encrypt_file_controlled(&input, &key_id, Vec::new(), &control, &mut reporter);
        assert!(matches!(result, Err(OperationError::Cancelled(_))));
        assert_eq!(fs::read(&input).unwrap(), b"keep the original file");
        assert!(!output.exists());
    }

    #[test]
    fn controlled_session_decrypt_cancellation_after_read_publishes_no_plaintext() {
        use crate::vault::{Algorithm, Purpose, Vault};
        let dir = TempDir::new().unwrap();
        let password = b"controlled-file-vault-password";
        let vault =
            Vault::create(dir.path().join("controlled-decrypt.nqv"), password, None).unwrap();
        let mut session = vault.unlock(password).unwrap();
        let key_id = session
            .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
            .unwrap();
        session.activate_key(&key_id).unwrap();
        let input = dir.path().join("source.txt");
        fs::write(&input, b"plaintext stays protected").unwrap();
        let encrypted = session.encrypt_file(&input, &key_id, Vec::new()).unwrap();
        let output = dir.path().join("restored.txt");
        let control = OperationControl::new();
        let mut reporter = |update: OperationProgress| {
            if update.phase == OperationPhase::ReadingInput && update.completed == update.total {
                control.cancel();
            }
        };
        let result = session.decrypt_file_controlled(&encrypted, &output, &control, &mut reporter);
        assert!(matches!(result, Err(OperationError::Cancelled(_))));
        assert!(!output.exists());
        assert!(encrypted.exists());
    }

    #[test]
    fn controlled_writer_cleans_up_when_cancelled_before_publish() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("cancelled.bin");
        let control = OperationControl::new();
        control.cancel();
        let result = write_new_atomic_controlled(&destination, b"secret", &control);
        assert!(matches!(result, Err(OperationError::Cancelled(_))));
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn controlled_writer_never_replaces_existing_destination() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("existing-controlled.bin");
        fs::write(&destination, b"original").unwrap();
        let result =
            write_new_atomic_controlled(&destination, b"replacement", &OperationControl::new());
        assert!(
            matches!(result, Err(OperationError::Failed(EnvelopeError::Io(error))) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn encrypted_path_appends_extension() {
        let p = encrypted_path_for(Path::new("doc.pdf"));
        assert_eq!(p, PathBuf::from("doc.pdf.nqx"));
    }

    #[test]
    fn encrypted_path_does_not_duplicate_extension() {
        let p = encrypted_path_for(Path::new("doc.pdf.nqx"));
        assert_eq!(p, PathBuf::from("doc.pdf.nqx"));
    }

    #[test]
    fn encrypted_path_keeps_parent_directory() {
        let p = encrypted_path_for(Path::new("/tmp/data/doc.pdf"));
        assert_eq!(p, PathBuf::from("/tmp/data/doc.pdf.nqx"));
    }

    #[test]
    fn encrypted_path_handles_files_without_extension() {
        let p = encrypted_path_for(Path::new("README"));
        assert_eq!(p, PathBuf::from("README.nqx"));
    }

    #[test]
    fn public_key_file_roundtrip() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("secret.txt");
        let output = dir.path().join("recovered.txt");
        let payload = b"the contents of the file";

        fs::write(&input, payload).unwrap();

        let pair = crate::crypto::kem::hybrid::generate();
        let recipient_pk = pair.public_key_bytes();

        let encrypted_path =
            encrypt_file_to_public_key(&input, &recipient_pk, b"secret.txt".to_vec()).unwrap();
        assert!(encrypted_path.exists());
        assert_eq!(encrypted_path, dir.path().join("secret.txt.nqx"));

        decrypt_file_with_kem(&encrypted_path, &output, &pair).unwrap();
        assert_eq!(fs::read(&output).unwrap(), payload);
    }

    #[test]
    fn public_key_file_rejects_wrong_recipient() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("secret.txt");
        let output = dir.path().join("recovered.txt");
        fs::write(&input, b"payload").unwrap();

        let alice = crate::crypto::kem::hybrid::generate();
        let bob = crate::crypto::kem::hybrid::generate();

        let encrypted_path =
            encrypt_file_to_public_key(&input, &alice.public_key_bytes(), Vec::new()).unwrap();

        // Bob cannot decrypt Alice's file.
        let err = decrypt_file_with_kem(&encrypted_path, &output, &bob).unwrap_err();
        assert!(matches!(err, EnvelopeError::Aead(_)));
        assert!(!output.exists());
    }

    #[test]
    fn public_key_file_missing_input() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("does-not-exist.txt");
        let pair = crate::crypto::kem::hybrid::generate();
        let err =
            encrypt_file_to_public_key(&input, &pair.public_key_bytes(), Vec::new()).unwrap_err();
        assert!(matches!(err, EnvelopeError::Io(_)));
    }

    #[test]
    fn vault_key_file_roundtrip() {
        use crate::vault::{
            Algorithm, KeyId, KeyMetadata, KeyStatus, Origin, Purpose, Timestamp,
            WrappedKeyMaterial,
        };

        let dir = TempDir::new().unwrap();
        let input = dir.path().join("message.txt");
        let output = dir.path().join("decrypted.txt");
        let payload = b"hello, vault";

        fs::write(&input, payload).unwrap();

        let kek = [0x42u8; 32];
        let rng = crate::crypto::random::OsRandomSource::new();
        let key_id = KeyId::generate(&rng, "aes256gcm").unwrap();
        let record = KeyRecord::new(
            KeyMetadata {
                key_id: key_id.clone(),
                algorithm: Algorithm::Aes256Gcm,
                purpose: Purpose::Encrypt,
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
            WrappedKeyMaterial::Symmetric(
                crate::vault::wrapping::wrap(&[0u8; 32], &kek, &key_id).unwrap(),
            ),
        );

        let encrypted_path =
            encrypt_file_with_key(&input, &kek, &record, b"message.txt".to_vec()).unwrap();
        assert!(encrypted_path.exists());

        let lookup_record = record.clone();
        let lookup = move |asked: &KeyId| {
            if asked == lookup_record.key_id() {
                Some(lookup_record.clone())
            } else {
                None
            }
        };

        decrypt_file_with_key(&encrypted_path, &output, &kek, lookup).unwrap();
        assert_eq!(fs::read(&output).unwrap(), payload);
    }
}

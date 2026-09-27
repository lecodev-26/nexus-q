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
//! ## Atomicity
//!
//! File operations use plain `std::fs::write` in this phase. The
//! atomic write pattern (temp file, fsync, rename, directory fsync)
//! that the vault uses is applied to vault files only. Applying it to
//! every `.nqx` file is a Phase 10 (Storage) concern.

use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::envelope::{self, EnvelopeError};
use super::key_id::KeyId;
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
    fs::write(&output, &envelope_bytes)?;
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
    fs::write(&output, &envelope_bytes)?;
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

/// Writes a `Zeroizing<Vec<u8>>` to disk, then drops the buffer.
///
/// On failure the destination is left as it was: `write_all` truncates
/// the file only after the buffer is accepted, and any partial write
/// is detected by the caller (the error is propagated).
fn write_zeroizing(path: &Path, data: &Zeroizing<Vec<u8>>) -> std::io::Result<()> {
    fs::write(path, data.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
                key_id,
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
            WrappedKeyMaterial::Symmetric(vec![0u8; 60]),
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

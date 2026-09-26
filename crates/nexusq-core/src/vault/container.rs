//! Vault object: the public entry point to a NEXUS-Q vault.
//!
//! A [`Vault`] represents a vault file on disk. It holds the path and
//! the parsed header, but never the key material. To use keys, the
//! caller must first [`Vault::unlock`] the vault with a password,
//! which produces a [`Session`] carrying the derived Key Encryption
//! Key (KEK) and the decrypted body in memory.
//!
//! See `docs/STORAGE.md` §4 and `docs/SECURITY_MODEL.md` §4.

use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::aead::{self, AeadError, Algorithm as AeadAlgorithm};
use crate::crypto::kdf::{self, KdfError};
use crate::crypto::random::{OsRandomSource, RandomError, RandomSource};

use super::algorithm::Algorithm;
use super::body::{CURRENT_SCHEMA_VERSION, VaultBody, VaultMetadata};
use super::header::{HeaderError, KdfParams, MAGIC, SALT_LEN, VaultHeader};
use super::key_id::{KeyId, KeyIdError};
use super::metadata::{KeyMetadata, Origin};
use super::purpose::Purpose;
use super::record::{KeyRecord, RecordValidationError, WrappedKeyMaterial};
use super::serde_helpers::{self, CborError};
use super::status::KeyStatus;
use super::timestamp::Timestamp;
use super::wrapping::{WrappingError, wrap};

/// Number of bytes of the length prefix before the CBOR header.
const HEADER_LEN_PREFIX: usize = 4;

/// Length of the AEAD nonce for the body.
const BODY_NONCE_LEN: usize = aead::NONCE_LEN;

/// Length of the AEAD tag for the body.
const BODY_TAG_LEN: usize = aead::TAG_LEN;

/// Default label used when the caller does not provide one.
const DEFAULT_LABEL: &str = "";

/// Errors returned by vault operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// An I/O error occurred while reading or writing the vault file.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The header was malformed or used an unsupported version.
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

    /// The supplied password is incorrect.
    #[error("wrong password")]
    WrongPassword,

    /// The vault file is malformed or truncated.
    #[error("vault file is corrupted: {0}")]
    Corrupt(&'static str),

    /// The vault file was not produced by this program.
    #[error("vault file has an invalid magic number")]
    BadMagic,

    /// The vault uses a version this build does not understand.
    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(u8),

    /// A key with this id already exists in the vault.
    #[error("key id already exists: {0}")]
    DuplicateKeyId(KeyId),

    /// The purpose is not allowed for the chosen algorithm.
    #[error("purpose {purpose} is not allowed for algorithm {algorithm}")]
    PurposeNotAllowed {
        /// The algorithm requested.
        algorithm: Algorithm,
        /// The purpose requested.
        purpose: Purpose,
    },

    /// Wrapping or unwrapping key material failed.
    #[error("wrapping error: {0}")]
    Wrapping(#[from] WrappingError),

    /// A key record failed its internal consistency check.
    #[error("record validation failed: {0}")]
    RecordValidation(#[from] RecordValidationError),

    /// Key id generation or parsing failed.
    #[error("key id error: {0}")]
    KeyId(#[from] KeyIdError),
}

/// A vault file on disk.
///
/// Does not hold key material. Use [`Vault::unlock`] to derive the KEK
/// and obtain a [`Session`].
#[derive(Debug, Clone)]
pub struct Vault {
    path: PathBuf,
    header: VaultHeader,
}

/// An unlocked vault session.
///
/// Holds the derived KEK and the decrypted body in memory. Dropping the
/// session zeroizes the KEK. Passing it back to [`Vault::lock`] persists
/// any changes and returns ownership of the [`Vault`].
#[derive(Debug)]
pub struct Session {
    vault: Vault,
    kek: Zeroizing<[u8; kdf::DERIVED_KEY_LEN]>,
    body: VaultBody,
}

impl Vault {
    /// Creates a new vault file at `path` and returns the in-memory
    /// [`Vault`] (locked).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written, if the password
    /// derivation fails, or if randomness is unavailable. If the file
    /// already exists, the operation fails with [`VaultError::Io`].
    pub fn create(
        path: impl AsRef<Path>,
        password: &[u8],
        label: Option<String>,
    ) -> Result<Self, VaultError> {
        let path = path.as_ref().to_path_buf();

        // Fail fast if the file already exists.
        if path.exists() {
            return Err(VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "vault file already exists",
            )));
        }

        let mut rng = OsRandomSource::new();

        // Generate a fresh salt and vault id.
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt)?;

        let vault_id = generate_vault_id(&mut rng)?;

        // Derive the KEK and build the header.
        let params = KdfParams::v1_default();
        let kek = derive_kek(password, &salt, &params)?;
        let header = VaultHeader::new(params, salt.to_vec(), kek.as_ref())?;

        // Build the initial (empty) body.
        let now = Timestamp::now().unwrap_or(Timestamp::from_secs(0));
        let metadata = VaultMetadata {
            vault_id,
            created_at: now,
            created_by: DEFAULT_LABEL.to_string(),
            label,
            schema_version: CURRENT_SCHEMA_VERSION,
        };
        let body = VaultBody::new(metadata);

        let vault = Self { path, header };
        vault.write_body(&body, &kek)?;

        Ok(vault)
    }

    /// Opens an existing vault file and parses its header.
    ///
    /// The vault is returned locked: no password is required to open
    /// the file, only to unlock it.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the header is
    /// malformed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, VaultError> {
        let path = path.as_ref().to_path_buf();
        let bytes = fs::read(&path)?;
        let (header, _rest) = parse_file(&bytes)?;
        Ok(Self { path, header })
    }

    /// Unlocks the vault with `password`, deriving the KEK and
    /// decrypting the body.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::WrongPassword`] if the derived verifier
    /// does not match, or another error if the body cannot be decrypted.
    pub fn unlock(&self, password: &[u8]) -> Result<Session, VaultError> {
        let kek = derive_kek(password, &self.header.salt, &self.header.kdf)?;

        // Check the verifier before touching the body.
        self.header
            .verify_kek(kek.as_ref())
            .map_err(|_| VaultError::WrongPassword)?;

        let body = self.read_body(&kek)?;

        Ok(Session {
            vault: self.clone(),
            kek,
            body,
        })
    }

    /// Returns the path of the vault file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the parsed header.
    #[must_use]
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Returns the vault id, as stored in the (still encrypted) body.
    ///
    /// This is `None` for a freshly opened vault, because the id lives
    /// inside the encrypted body. Callers must unlock the vault to
    /// obtain it.
    ///
    /// Note: a future revision may hoist the vault id into the header
    /// as an unencrypted, authenticated field, so that vaults can be
    /// correlated without unlocking them.
    #[must_use]
    pub const fn vault_id_from_body_hint(&self) -> Option<&str> {
        None
    }

    // =========================================================================
    // Internal
    // =========================================================================

    fn read_body(&self, kek: &[u8; kdf::DERIVED_KEY_LEN]) -> Result<VaultBody, VaultError> {
        let bytes = fs::read(&self.path)?;
        let (header, rest) = parse_file(&bytes)?;

        if rest.len() < BODY_NONCE_LEN + BODY_TAG_LEN {
            return Err(VaultError::Corrupt("body is truncated"));
        }
        let (nonce, ciphertext) = rest.split_at(BODY_NONCE_LEN);

        let header_bytes = serde_helpers::to_vec(&header)?;
        let plaintext = aead::decrypt(
            AeadAlgorithm::Aes256Gcm,
            kek,
            nonce,
            &header_bytes,
            ciphertext,
        )
        .map_err(|_| VaultError::WrongPassword)?;

        let body: VaultBody = serde_helpers::from_slice(&plaintext)?;
        Ok(body)
    }

    fn write_body(
        &self,
        body: &VaultBody,
        kek: &[u8; kdf::DERIVED_KEY_LEN],
    ) -> Result<(), VaultError> {
        let mut rng = OsRandomSource::new();
        let mut nonce = [0u8; BODY_NONCE_LEN];
        rng.fill_bytes(&mut nonce)?;

        let body_bytes = serde_helpers::to_vec(body)?;
        let header_bytes = serde_helpers::to_vec(&self.header)?;

        let ciphertext = aead::encrypt(
            AeadAlgorithm::Aes256Gcm,
            kek,
            &nonce,
            &header_bytes,
            &body_bytes,
        )?;

        write_vault_file(&self.path, &header_bytes, &nonce, &ciphertext)?;
        Ok(())
    }
}

impl Session {
    /// Returns a reference to the vault this session belongs to.
    #[must_use]
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Returns a reference to the decrypted body.
    #[must_use]
    pub fn body(&self) -> &VaultBody {
        &self.body
    }

    /// Returns a mutable reference to the decrypted body.
    ///
    /// Mutations are only persisted when the session is passed back to
    /// [`Vault::lock`].
    pub fn body_mut(&mut self) -> &mut VaultBody {
        &mut self.body
    }

    /// Generates a new key of the given algorithm and purpose.
    ///
    /// The material is generated (as a placeholder for now: 32 random
    /// bytes regardless of algorithm), wrapped under the vault's KEK,
    /// and stored in the body. The key starts in the `Generated`
    /// state; activation is a separate step performed by the caller.
    ///
    /// See `docs/KEY_MANAGEMENT.md` §6.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::PurposeNotAllowed`] if the purpose is not
    /// compatible with the algorithm, [`VaultError::DuplicateKeyId`]
    /// if the freshly generated id collides (astronomically unlikely),
    /// or another error if generation or wrapping fails.
    pub fn generate_key(
        &mut self,
        algorithm: Algorithm,
        purpose: Purpose,
    ) -> Result<KeyId, VaultError> {
        if !purpose.is_allowed_for(algorithm) {
            return Err(VaultError::PurposeNotAllowed { algorithm, purpose });
        }

        // Generate the key id and the material.
        let mut rng = OsRandomSource::new();
        let key_id = KeyId::generate(&mut rng, algorithm.as_str())?;
        if self.body.find_key(&key_id).is_some() {
            return Err(VaultError::DuplicateKeyId(key_id));
        }

        let material = generate_material(algorithm, &mut rng)?;

        // Wrap the material under the KEK, bound to the key id.
        let wrapped = wrap(&material, self.kek.as_ref(), &key_id)?;

        // Pick the WrappedKeyMaterial variant based on the algorithm's
        // category. Symmetric algorithms use Symmetric; the rest use
        // Asymmetric. Hardware-backed keys are not produced here.
        let wrapped_variant = match algorithm.category() {
            super::algorithm::Category::Aead => WrappedKeyMaterial::Symmetric(wrapped),
            _ => WrappedKeyMaterial::Asymmetric(wrapped),
        };

        // Build the metadata record.
        let now = Timestamp::now().unwrap_or(Timestamp::from_secs(0));
        let metadata = KeyMetadata {
            key_id: key_id.clone(),
            algorithm,
            purpose,
            created_at: now,
            created_by: "session".to_string(),
            created_from: Origin::Generated,
            status: KeyStatus::Generated,
            version: 1,
            owner: None,
            rotation_due: None,
            expires_at: None,
            parent_key_id: None,
            hardware_backed: false,
            attestation: None,
        };

        let record = KeyRecord::new(metadata, wrapped_variant);
        record.validate()?;

        self.body.keys.push(record);
        Ok(key_id)
    }

    /// Returns an iterator over all key records in the vault.
    pub fn list_keys(&self) -> impl Iterator<Item = &KeyRecord> {
        self.body.keys.iter()
    }

    /// Returns the key record for `key_id`, if present.
    #[must_use]
    pub fn find_key(&self, key_id: &KeyId) -> Option<&KeyRecord> {
        self.body.find_key(key_id)
    }

    /// Returns a mutable reference to the key record for `key_id`.
    pub fn find_key_mut(&mut self, key_id: &KeyId) -> Option<&mut KeyRecord> {
        self.body.find_key_mut(key_id)
    }

    /// Returns the number of keys in the vault.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.body.key_count()
    }

    /// Locks the session: persists the current body and returns the
    /// [`Vault`].
    ///
    /// # Errors
    ///
    /// Returns an error if the body cannot be re-encrypted or the file
    /// cannot be written.
    pub fn lock(self) -> Result<Vault, VaultError> {
        self.vault.write_body(&self.body, &self.kek)?;
        Ok(self.vault)
    }
}

// =============================================================================
// File layout
// =============================================================================
//
// [MAGIC: 4 bytes]
// [header_cbor_len: u32 BE]
// [header_cbor: N bytes]
// [body_nonce: 12 bytes]
// [body_ciphertext_and_tag: M bytes]

fn parse_file(bytes: &[u8]) -> Result<(VaultHeader, &[u8]), VaultError> {
    if bytes.len() < MAGIC.len() + HEADER_LEN_PREFIX {
        return Err(VaultError::Corrupt("file too small"));
    }
    let (magic, rest) = bytes.split_at(MAGIC.len());
    if magic != MAGIC {
        return Err(VaultError::BadMagic);
    }

    let (len_bytes, rest) = rest.split_at(HEADER_LEN_PREFIX);
    let header_len = u32::from_be_bytes(len_bytes.try_into().expect("4 bytes")) as usize;

    if rest.len() < header_len {
        return Err(VaultError::Corrupt("header length exceeds file size"));
    }
    let (header_bytes, rest) = rest.split_at(header_len);

    let header: VaultHeader = serde_helpers::from_slice(header_bytes)?;
    if !header.is_supported() {
        return Err(VaultError::UnsupportedVersion(header.version));
    }

    Ok((header, rest))
}

fn write_vault_file(
    path: &Path,
    header_bytes: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), VaultError> {
    let header_len =
        u32::try_from(header_bytes.len()).map_err(|_| VaultError::Corrupt("header too large"))?;

    let mut out = Vec::with_capacity(
        MAGIC.len() + HEADER_LEN_PREFIX + header_bytes.len() + nonce.len() + ciphertext.len(),
    );
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&header_len.to_be_bytes());
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);

    // Atomic write: temp file in the same directory, then rename.
    // This avoids the caller ever seeing a half-written file.
    let tmp = path.with_extension("nqv.tmp");
    fs::write(&tmp, &out)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn derive_kek(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; kdf::DERIVED_KEY_LEN]>, VaultError> {
    // Only Argon2id is supported in v1; unknown values will be rejected
    // at header parse time once more algorithms are added.
    let _ = params.algorithm;
    let kek = kdf::argon2id(password, salt)?;
    Ok(Zeroizing::new(kek))
}

fn generate_vault_id<S: RandomSource>(source: &mut S) -> Result<String, VaultError> {
    let mut buf = [0u8; 16];
    source.fill_bytes(&mut buf)?;
    let mut out = String::with_capacity(4 + 32);
    out.push_str("nqv_");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in buf {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    Ok(out)
}

// =============================================================================
// Key material generation
// =============================================================================
//
// For Phase 4 the vault is a container: it does not yet need to know
// how to produce algorithm-specific key material. That arrives with
// envelope encryption (Phase 5) and identity (Phase 6). For now we
// generate 32 random bytes regardless of algorithm, which is enough to
// exercise the wrapping and storage paths.
//
// When real material is introduced, this function will dispatch per
// algorithm and return the serialized private key bytes.

fn generate_material<S: RandomSource>(
    _algorithm: Algorithm,
    source: &mut S,
) -> Result<Vec<u8>, VaultError> {
    let mut material = vec![0u8; 32];
    source.fill_bytes(&mut material)?;
    Ok(material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_path(dir: &TempDir, name: &str) -> PathBuf {
        dir.path().join(name)
    }

    #[test]
    fn create_then_open_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");

        let vault = Vault::create(&path, b"correct horse", Some("test".to_string())).unwrap();
        assert!(path.exists());
        assert_eq!(vault.path(), path.as_path());

        let opened = Vault::open(&path).unwrap();
        assert_eq!(opened.header().magic, MAGIC);
    }

    #[test]
    fn create_refuses_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"a", None).unwrap();
        let err = Vault::create(&path, b"b", None).unwrap_err();
        assert!(matches!(err, VaultError::Io(_)));
    }

    #[test]
    fn unlock_with_correct_password_succeeds() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");

        Vault::create(&path, b"correct horse", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"correct horse").unwrap();
        assert_eq!(session.body().key_count(), 0);
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");

        Vault::create(&path, b"correct horse", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let err = vault.unlock(b"wrong").unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword));
    }

    #[test]
    fn lock_after_modifications_persists_them() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");

        Vault::create(&path, b"pw", None).unwrap();

        // Unlock, modify, lock.
        {
            let vault = Vault::open(&path).unwrap();
            let mut session = vault.unlock(b"pw").unwrap();
            session.body_mut().metadata.label = Some("renamed".to_string());
            session.lock().unwrap();
        }

        // Reopen and verify.
        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        assert_eq!(session.body().metadata.label.as_deref(), Some("renamed"));
    }

    #[test]
    fn open_rejects_file_with_wrong_magic() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "bad.nqv");
        fs::write(&path, b"XXXX\x00\x00\x00\x00").unwrap();
        let err = Vault::open(&path).unwrap_err();
        assert!(matches!(err, VaultError::BadMagic));
    }

    #[test]
    fn open_rejects_truncated_file() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "trunc.nqv");
        fs::write(&path, b"NQ").unwrap();
        let err = Vault::open(&path).unwrap_err();
        assert!(matches!(err, VaultError::Corrupt(_)));
    }

    #[test]
    fn tampering_with_header_breaks_body_decryption() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");

        Vault::create(&path, b"pw", None).unwrap();

        // Flip a byte somewhere in the header region.
        let mut bytes = fs::read(&path).unwrap();
        let header_start = MAGIC.len() + HEADER_LEN_PREFIX;
        bytes[header_start] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        // Now the header is corrupted. Opening may or may not succeed
        // (CBOR is strict), but unlocking must fail: either the header
        // no longer parses, or the AAD no longer matches.
        match Vault::open(&path) {
            Ok(vault) => {
                let err = vault.unlock(b"pw").unwrap_err();
                assert!(matches!(
                    err,
                    VaultError::WrongPassword | VaultError::Cbor(_)
                ));
            }
            Err(_) => {
                // Rejected at open time: acceptable.
            }
        }
    }

    #[test]
    fn vault_id_has_expected_prefix() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        assert!(session.body().metadata.vault_id.starts_with("nqv_"));
        assert_eq!(session.body().metadata.vault_id.len(), 4 + 32);
    }

    #[test]
    fn generate_key_stores_a_wrapped_record() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();
        assert_eq!(session.key_count(), 1);

        let record = session.find_key(&id).unwrap();
        assert_eq!(record.algorithm(), Algorithm::Ed25519);
        assert_eq!(record.purpose(), Purpose::Sign);
        assert_eq!(record.status(), KeyStatus::Generated);
        // Wrapped material is longer than the 32-byte plaintext because
        // it carries a nonce (12) and a tag (16).
        assert_eq!(record.material.len(), 12 + 32 + 16);
    }

    #[test]
    fn generate_key_rejects_incompatible_purpose() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        // Ed25519 cannot be used for encryption.
        let err = session
            .generate_key(Algorithm::Ed25519, Purpose::Encrypt)
            .unwrap_err();
        assert!(matches!(err, VaultError::PurposeNotAllowed { .. }));
        assert_eq!(session.key_count(), 0);
    }

    #[test]
    fn generated_keys_persist_across_lock_and_unlock() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();

        let id = {
            let vault = Vault::open(&path).unwrap();
            let mut session = vault.unlock(b"pw").unwrap();
            let id = session
                .generate_key(Algorithm::Aes256Gcm, Purpose::Wrap)
                .unwrap();
            session.lock().unwrap();
            id
        };

        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        assert_eq!(session.key_count(), 1);
        assert!(session.find_key(&id).is_some());
    }

    #[test]
    fn generated_keys_have_distinct_ids() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let a = session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();
        let b = session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();
        assert_ne!(a, b);
        assert_eq!(session.key_count(), 2);
    }

    #[test]
    fn list_keys_iterates_every_record() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();
        session
            .generate_key(Algorithm::MlKem768, Purpose::KeyAgreement)
            .unwrap();

        let ids: Vec<_> = session.list_keys().map(|r| r.key_id().clone()).collect();
        assert_eq!(ids.len(), 2);
    }
}

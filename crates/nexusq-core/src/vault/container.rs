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
use std::io::Write as _;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::aead::{self, AeadError, Algorithm as AeadAlgorithm};
use crate::crypto::kdf::{self, KdfError};
use crate::crypto::random::{OsRandomSource, RandomError, RandomSource};

use super::algorithm::Algorithm;
use super::body::{CURRENT_SCHEMA_VERSION, VaultBody, VaultMetadata};
use super::envelope::{self, EnvelopeError};
use super::header::{HeaderError, KdfParams, MAGIC, SALT_LEN, VaultHeader};
use super::key_id::{KeyId, KeyIdError};
use super::lifecycle::{DestructionConfirmation, LifecycleError, RevokeReason};
use super::metadata::{KeyMetadata, Origin};
use super::purpose::Purpose;
use super::record::{KeyRecord, RecordValidationError, WrappedKeyMaterial};
use super::serde_helpers::{self, CborError};
use super::state::{StateTransitionError, VaultState};
use super::status::KeyStatus;
use super::timestamp::Timestamp;
use super::wrapping::{WrappingError, wrap};
use crate::crypto::sign::{self, SignError, Signature};
use crate::identity::{
    Credential, CredentialError, Identity, IdentityId, IdentityMetadata, IdentityStatus,
};

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

    /// The session's state does not allow the requested operation.
    #[error("operation not allowed in vault state {state}")]
    StateDenied {
        /// The state that refused the operation.
        state: VaultState,
    },

    /// A vault state transition was not allowed.
    #[error("invalid vault state transition: {0}")]
    StateTransition(#[from] StateTransitionError),

    /// A key lifecycle operation failed.
    #[error("lifecycle error: {0}")]
    Lifecycle(#[from] LifecycleError),

    /// An envelope operation failed.
    #[error("envelope error: {0}")]
    Envelope(#[from] EnvelopeError),

    /// An identity operation failed.
    #[error("identity error: {0}")]
    Identity(#[from] crate::identity::IdentityValidationError),

    /// No identity with this id exists in the vault.
    #[error("identity not found: {0}")]
    IdentityNotFound(IdentityId),

    /// An identity id was generated twice (astronomically unlikely).
    #[error("identity id already exists: {0}")]
    DuplicateIdentityId(IdentityId),

    /// A signature operation failed.
    #[error("signature error: {0}")]
    Signature(#[from] SignError),

    /// The identity is not in a state that allows the operation.
    #[error("identity {id} is {status}; cannot be used for this operation")]
    IdentityNotUsable {
        /// The identity in question.
        id: IdentityId,
        /// Its current status.
        status: IdentityStatus,
    },

    /// A key needed by an identity operation is missing or has no
    /// public half.
    #[error("key {0} has no public half")]
    MissingPublicKey(KeyId),

    /// A credential operation failed.
    #[error("credential error: {0}")]
    Credential(#[from] CredentialError),
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
    state: VaultState,
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

        let rng = OsRandomSource::new();

        // Generate a fresh salt and vault id.
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt)?;

        let vault_id = generate_vault_id(&rng)?;

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
            state: VaultState::Unlocked,
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
        let rng = OsRandomSource::new();
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
        self.require_writes_allowed()?;

        if !purpose.is_allowed_for(algorithm) {
            return Err(VaultError::PurposeNotAllowed { algorithm, purpose });
        }

        // Generate the key id and the material.
        let rng = OsRandomSource::new();
        let key_id = KeyId::generate(&rng, algorithm.as_str())?;
        if self.body.find_key(&key_id).is_some() {
            return Err(VaultError::DuplicateKeyId(key_id));
        }

        let (material, public_key_bytes) = generate_material(algorithm, &rng)?;

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

        let record = match public_key_bytes {
            Some(pk) => KeyRecord::with_public_key(metadata, wrapped_variant, pk),
            None => KeyRecord::new(metadata, wrapped_variant),
        };
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
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateDenied`] if the session is sealed or
    /// compromised. Read the immutable [`Session::find_key`] for
    /// read-only access.
    pub fn find_key_mut(&mut self, key_id: &KeyId) -> Result<Option<&mut KeyRecord>, VaultError> {
        self.require_writes_allowed()?;
        Ok(self.body.find_key_mut(key_id))
    }

    /// Returns the number of keys in the vault.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.body.key_count()
    }

    /// Returns the current state of the session.
    #[must_use]
    pub const fn state(&self) -> VaultState {
        self.state
    }

    /// Seals the session: reads remain allowed, writes are refused.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateTransition`] if the transition is not
    /// allowed (for example, from a compromised session).
    pub fn seal(&mut self) -> Result<(), VaultError> {
        self.state = self.state.transition_to(VaultState::Sealed)?;
        Ok(())
    }

    /// Unseals the session, returning it to the unlocked state.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateTransition`] if the transition is not
    /// allowed (for example, from a compromised session).
    pub fn unseal(&mut self) -> Result<(), VaultError> {
        self.state = self.state.transition_to(VaultState::Unlocked)?;
        Ok(())
    }

    /// Marks the session as compromised. All further operations are
    /// refused; the caller must drop the session.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateTransition`] if the session is already
    /// locked or compromised.
    pub fn mark_compromised(&mut self) -> Result<(), VaultError> {
        self.state = self.state.transition_to(VaultState::Compromised)?;
        Ok(())
    }

    // =========================================================================
    // Identity operations
    // =========================================================================

    /// Creates a fresh identity with a brand new Ed25519 signing key.
    ///
    /// The signing key is generated inside the vault and immediately
    /// activated. The new identity references it and starts in the
    /// `Active` state.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateDenied`] if the session is sealed or
    /// compromised, or another error if key generation or identity
    /// registration fails.
    pub fn create_identity(&mut self, label: Option<String>) -> Result<IdentityId, VaultError> {
        self.require_writes_allowed()?;

        // Generate the signing key inside the vault.
        let signing_key = self.generate_key(Algorithm::Ed25519, Purpose::Sign)?;
        self.activate_key(&signing_key)?;

        // Build the identity.
        let rng = OsRandomSource::new();
        let identity_id = IdentityId::generate(&rng)
            .map_err(|_| VaultError::Random(crate::crypto::random::RandomError::Unavailable))?;

        if self.body.find_identity(&identity_id).is_some() {
            return Err(VaultError::DuplicateIdentityId(identity_id));
        }

        let now = Timestamp::now().unwrap_or(Timestamp::from_secs(0));
        let metadata = IdentityMetadata {
            created_at: now,
            created_by: "session".to_string(),
            label,
            status: IdentityStatus::Active,
            version: 1,
            revoked_at: None,
            revocation_reason: None,
        };

        let identity = Identity {
            id: identity_id.clone(),
            signing_key,
            encryption_key: None,
            key_agreement_key: None,
            metadata,
        };
        identity.validate()?;

        self.body.identities.push(identity);
        Ok(identity_id)
    }

    /// Returns an iterator over all identities in the vault.
    pub fn list_identities(&self) -> impl Iterator<Item = &Identity> {
        self.body.identities.iter()
    }

    /// Returns the identity with `id`, if present.
    #[must_use]
    pub fn find_identity(&self, id: &IdentityId) -> Option<&Identity> {
        self.body.find_identity(id)
    }

    /// Returns a mutable reference to the identity with `id`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateDenied`] if the session is sealed or
    /// compromised.
    pub fn find_identity_mut(
        &mut self,
        id: &IdentityId,
    ) -> Result<Option<&mut Identity>, VaultError> {
        self.require_writes_allowed()?;
        Ok(self.body.find_identity_mut(id))
    }

    /// Returns the number of identities in the vault.
    #[must_use]
    pub fn identity_count(&self) -> usize {
        self.body.identity_count()
    }

    /// Signs `message` on behalf of the identity.
    ///
    /// The signing key is unwrapped from the vault with the KEK,
    /// used, and dropped (zeroized) before returning.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::IdentityNotFound`] if the identity does
    /// not exist, [`VaultError::IdentityNotUsable`] if it is not
    /// Active, [`VaultError::Lifecycle`] if the signing key is not
    /// Active, or another error if unwrapping or signing fails.
    pub fn identity_sign(&self, id: &IdentityId, message: &[u8]) -> Result<Signature, VaultError> {
        let identity = self
            .body
            .find_identity(id)
            .ok_or_else(|| VaultError::IdentityNotFound(id.clone()))?;

        if identity.metadata.status != IdentityStatus::Active {
            return Err(VaultError::IdentityNotUsable {
                id: id.clone(),
                status: identity.metadata.status,
            });
        }

        let record = self
            .body
            .find_key(&identity.signing_key)
            .ok_or_else(|| LifecycleError::KeyNotFound(identity.signing_key.clone()))?;

        if record.algorithm() != Algorithm::Ed25519 {
            return Err(VaultError::Envelope(EnvelopeError::WrongCategory {
                key_id: identity.signing_key.clone(),
                algorithm: record.algorithm(),
            }));
        }
        if record.status() != KeyStatus::Active {
            return Err(VaultError::IdentityNotUsable {
                id: id.clone(),
                status: identity.metadata.status,
            });
        }

        // Unwrap the seed, reconstruct the signing key, sign.
        let seed_bytes = super::wrapping::unwrap(
            record.material.bytes(),
            self.kek.as_ref(),
            &identity.signing_key,
        )?;
        let signing_key = sign::SigningKey::from_bytes(&seed_bytes)?;
        let signature = signing_key.sign(message);
        Ok(signature)
    }

    /// Verifies a signature produced by [`Session::identity_sign`].
    ///
    /// Does **not** require the KEK: the identity's public key is
    /// stored in cleartext on the key record.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::IdentityNotFound`] if the identity does
    /// not exist, [`VaultError::MissingPublicKey`] if the signing key
    /// record has no public half, or [`VaultError::Signature`] if the
    /// signature does not match.
    pub fn identity_verify(
        &self,
        id: &IdentityId,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), VaultError> {
        let identity = self
            .body
            .find_identity(id)
            .ok_or_else(|| VaultError::IdentityNotFound(id.clone()))?;

        let record = self
            .body
            .find_key(&identity.signing_key)
            .ok_or_else(|| LifecycleError::KeyNotFound(identity.signing_key.clone()))?;

        let pk_bytes = record
            .public_key_bytes()
            .ok_or_else(|| VaultError::MissingPublicKey(identity.signing_key.clone()))?;

        let verifying_key = sign::VerifyingKey::from_bytes(pk_bytes)?;
        verifying_key.verify(message, signature)?;
        Ok(())
    }

    /// Rotates the signing key of an identity.
    ///
    /// Generates a new Ed25519 key, activates it, retires the previous
    /// one, and bumps the identity's version. The identity keeps its
    /// [`IdentityId`]; only the signing key changes.
    ///
    /// During the rotation the identity transitions through
    /// `Rotating` but ends in `Active` in the same call. The
    /// intermediate state exists in the enum for future use (for
    /// example, to schedule re-signing of long-lived artifacts), but
    /// the current implementation does not expose it to callers.
    ///
    /// Returns the new signing key's [`KeyId`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::IdentityNotFound`] if the identity does
    /// not exist, [`VaultError::IdentityNotUsable`] if it is not
    /// `Active`, or another error if key generation or retirement
    /// fails.
    pub fn rotate_identity_key(&mut self, id: &IdentityId) -> Result<KeyId, VaultError> {
        self.require_writes_allowed()?;

        // Snapshot what we need before mutating.
        let (old_signing_key, current_version) = {
            let identity = self
                .body
                .find_identity(id)
                .ok_or_else(|| VaultError::IdentityNotFound(id.clone()))?;

            if identity.metadata.status != IdentityStatus::Active {
                return Err(VaultError::IdentityNotUsable {
                    id: id.clone(),
                    status: identity.metadata.status,
                });
            }
            (identity.signing_key.clone(), identity.metadata.version)
        };

        // Generate the replacement signing key and activate it.
        let new_signing_key = self.generate_key(Algorithm::Ed25519, Purpose::Sign)?;
        self.activate_key(&new_signing_key)?;

        // Retire the old key: Active -> Rotating -> Retired.
        {
            let old_record = self
                .body
                .find_key_mut(&old_signing_key)
                .ok_or_else(|| LifecycleError::KeyNotFound(old_signing_key.clone()))?;
            let rotating = old_record
                .metadata
                .status
                .transition_to(KeyStatus::Rotating)
                .map_err(LifecycleError::from)?;
            let retired = rotating
                .transition_to(KeyStatus::Retired)
                .map_err(LifecycleError::from)?;
            old_record.metadata.status = retired;
        }

        // Update the identity: swap the signing key, bump the version.
        {
            let identity = self.body.find_identity_mut(id).expect("checked above");
            identity.signing_key = new_signing_key.clone();
            identity.metadata.version = current_version + 1;
        }

        Ok(new_signing_key)
    }

    /// Revokes an identity.
    ///
    /// Revocation is terminal: the identity cannot return to `Active`.
    /// Past signatures remain verifiable because the signing key's
    /// public half stays in the vault; new signatures are refused.
    ///
    /// The signing key itself is **not** revoked here. Its status is
    /// independent of the identity's, and the identity check already
    /// blocks new operations. Callers who also want to revoke the key
    /// should call [`Session::revoke_key`] explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::IdentityNotFound`] if the identity does
    /// not exist, [`VaultError::IdentityNotUsable`] if it is already
    /// revoked, or [`VaultError::StateDenied`] if the session is sealed
    /// or compromised.
    pub fn revoke_identity(
        &mut self,
        id: &IdentityId,
        reason: RevokeReason,
    ) -> Result<(), VaultError> {
        self.require_writes_allowed()?;

        let now = Timestamp::now().unwrap_or(Timestamp::from_secs(0));

        let identity = self
            .body
            .find_identity_mut(id)
            .ok_or_else(|| VaultError::IdentityNotFound(id.clone()))?;

        if identity.metadata.status == IdentityStatus::Revoked {
            return Err(VaultError::IdentityNotUsable {
                id: id.clone(),
                status: IdentityStatus::Revoked,
            });
        }

        let new_status = identity
            .metadata
            .status
            .transition_to(IdentityStatus::Revoked)
            .map_err(|_| VaultError::IdentityNotUsable {
                id: id.clone(),
                status: identity.metadata.status,
            })?;

        identity.metadata.status = new_status;
        identity.metadata.revoked_at = Some(now);
        identity.metadata.revocation_reason = Some(reason);
        Ok(())
    }

    // =========================================================================
    // Credential operations
    // =========================================================================

    /// Issues a credential signed by `issuer` about `subject`.
    ///
    /// Returns a self-contained CBOR-encoded blob. The credential is
    /// **not** stored in the vault; the caller decides where to keep
    /// it. Any holder of the issuer's public signing key can verify it.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::IdentityNotFound`] if the issuer does not
    /// exist, [`VaultError::IdentityNotUsable`] if the issuer is not
    /// `Active`, or another error if the signing key cannot be used.
    pub fn issue_credential(
        &self,
        issuer: &IdentityId,
        subject: IdentityId,
        claims: Vec<u8>,
        expires_at: Option<Timestamp>,
    ) -> Result<Vec<u8>, VaultError> {
        // Signing requires write access, because it unwraps key material.
        self.require_writes_allowed()?;

        let identity = self
            .body
            .find_identity(issuer)
            .ok_or_else(|| VaultError::IdentityNotFound(issuer.clone()))?;

        if identity.metadata.status != IdentityStatus::Active {
            return Err(VaultError::IdentityNotUsable {
                id: issuer.clone(),
                status: identity.metadata.status,
            });
        }

        let record = self
            .body
            .find_key(&identity.signing_key)
            .ok_or_else(|| LifecycleError::KeyNotFound(identity.signing_key.clone()))?;

        if record.status() != KeyStatus::Active {
            return Err(VaultError::IdentityNotUsable {
                id: issuer.clone(),
                status: identity.metadata.status,
            });
        }

        // Unwrap the seed, rebuild the signing key, issue.
        let seed_bytes = super::wrapping::unwrap(
            record.material.bytes(),
            self.kek.as_ref(),
            &identity.signing_key,
        )?;
        let signing_key = sign::SigningKey::from_bytes(&seed_bytes)?;

        let now = Timestamp::now().unwrap_or(Timestamp::from_secs(0));
        let credential_bytes = Credential::issue(
            &signing_key,
            issuer.clone(),
            subject,
            claims,
            now,
            expires_at,
        )?;
        Ok(credential_bytes)
    }

    /// Verifies a credential using the issuer's public signing key.
    ///
    /// Does not check expiry: callers that need expiry enforcement
    /// should inspect [`Credential::is_expired_at`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Credential`] if the bytes are malformed or
    /// the signature does not verify, or
    /// [`VaultError::IdentityNotFound`] if the issuer is not in the
    /// vault.
    pub fn verify_credential(&self, bytes: &[u8]) -> Result<Credential, VaultError> {
        // Parse once to learn who the issuer is.
        let credential: Credential = crate::vault::from_slice(bytes)?;

        let identity = self
            .body
            .find_identity(&credential.issuer)
            .ok_or_else(|| VaultError::IdentityNotFound(credential.issuer.clone()))?;

        let record = self
            .body
            .find_key(&identity.signing_key)
            .ok_or_else(|| LifecycleError::KeyNotFound(identity.signing_key.clone()))?;

        let pk_bytes = record
            .public_key_bytes()
            .ok_or_else(|| VaultError::MissingPublicKey(identity.signing_key.clone()))?;

        let verifying_key = sign::VerifyingKey::from_bytes(pk_bytes)?;
        let verified = Credential::verify_with_key(bytes, &verifying_key)?;
        Ok(verified)
    }

    // =========================================================================
    // Envelope operations
    // =========================================================================

    /// Encrypts `plaintext` with the vault key `key_id`, producing a
    /// CBOR-encoded envelope.
    ///
    /// The key must be `Active` and of an AEAD category.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateDenied`] if the session is sealed or
    /// compromised, or [`VaultError::Envelope`] for envelope-level
    /// failures (unknown key, wrong category, non-active key).
    pub fn encrypt(
        &self,
        key_id: &KeyId,
        plaintext: &[u8],
        metadata: Vec<u8>,
    ) -> Result<Vec<u8>, VaultError> {
        self.require_writes_allowed()?;

        let record = self
            .body
            .find_key(key_id)
            .ok_or_else(|| LifecycleError::KeyNotFound(key_id.clone()))?;

        let bytes = envelope::build_envelope(self.kek.as_ref(), record, plaintext, metadata)?;
        Ok(bytes)
    }

    /// Decrypts a CBOR-encoded envelope produced by [`Session::encrypt`].
    ///
    /// The KeyId embedded in the envelope is resolved against the
    /// session's vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateDenied`] if the session is sealed or
    /// compromised, or [`VaultError::Envelope`] for envelope-level
    /// failures (unknown key, tampered data, wrong mode).
    pub fn decrypt(&self, envelope_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.require_writes_allowed()?;

        let lookup = |id: &KeyId| self.body.find_key(id).cloned();
        let plaintext = envelope::open_envelope(self.kek.as_ref(), envelope_bytes, lookup)?;
        Ok(plaintext)
    }

    /// Encrypts a file under the vault key `key_id`.
    ///
    /// The encrypted output is written next to `input` with a `.nqx`
    /// extension. Returns the path of the encrypted file.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateDenied`] if the session is sealed or
    /// compromised, or [`VaultError::Envelope`] for envelope-level
    /// failures.
    pub fn encrypt_file(
        &self,
        input: impl AsRef<std::path::Path>,
        key_id: &KeyId,
        metadata: Vec<u8>,
    ) -> Result<std::path::PathBuf, VaultError> {
        self.require_writes_allowed()?;

        let record = self
            .body
            .find_key(key_id)
            .ok_or_else(|| LifecycleError::KeyNotFound(key_id.clone()))?;

        let path =
            super::file_ops::encrypt_file_with_key(input, self.kek.as_ref(), record, metadata)?;
        Ok(path)
    }

    /// Decrypts an envelope file previously produced by
    /// [`Session::encrypt_file`], writing the plaintext to `output`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::StateDenied`] if the session is sealed or
    /// compromised, or [`VaultError::Envelope`] for envelope-level
    /// failures.
    pub fn decrypt_file(
        &self,
        input: impl AsRef<std::path::Path>,
        output: impl AsRef<std::path::Path>,
    ) -> Result<(), VaultError> {
        self.require_writes_allowed()?;

        let lookup = |id: &KeyId| self.body.find_key(id).cloned();
        super::file_ops::decrypt_file_with_key(input, output, self.kek.as_ref(), lookup)?;
        Ok(())
    }

    // =========================================================================
    // Key lifecycle operations
    // =========================================================================

    /// Moves a key from `Generated` to `Active`.
    ///
    /// The key becomes usable for new work.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Lifecycle`] with
    /// [`LifecycleError::KeyNotFound`] if the key does not exist, or
    /// [`LifecycleError::WrongStatus`] if it is not in `Generated`.
    pub fn activate_key(&mut self, key_id: &KeyId) -> Result<(), VaultError> {
        self.require_writes_allowed()?;
        let record = self
            .body
            .find_key_mut(key_id)
            .ok_or_else(|| LifecycleError::KeyNotFound(key_id.clone()))?;

        let new_status = record
            .metadata
            .status
            .transition_to(KeyStatus::Active)
            .map_err(LifecycleError::from)?;
        record.metadata.status = new_status;
        Ok(())
    }

    /// Rotates an `Active` key, producing a fresh key with the same
    /// algorithm and purpose, and retires the original.
    ///
    /// The new key carries `parent_key_id = Some(old)` and
    /// `version = old.version + 1`. It starts in `Generated`; the
    /// caller typically activates it explicitly.
    ///
    /// The original moves to `Retired`. It can still decrypt and verify
    /// data protected while it was active, but cannot produce new
    /// signatures or ciphertexts.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Lifecycle`] with
    /// [`LifecycleError::KeyNotFound`] if the key does not exist, or
    /// [`LifecycleError::WrongStatus`] if it is not `Active`.
    pub fn rotate_key(&mut self, key_id: &KeyId) -> Result<KeyId, VaultError> {
        self.require_writes_allowed()?;

        // Read the pieces we need before mutating anything.
        let (algorithm, purpose, old_version) = {
            let record = self
                .body
                .find_key(key_id)
                .ok_or_else(|| LifecycleError::KeyNotFound(key_id.clone()))?;
            if record.status() != KeyStatus::Active {
                return Err(LifecycleError::WrongStatus {
                    key_id: key_id.clone(),
                    status: record.status(),
                    required: "Active",
                }
                .into());
            }
            (
                record.algorithm(),
                record.purpose(),
                record.metadata.version,
            )
        };

        // Generate the replacement.
        let new_id = self.generate_key(algorithm, purpose)?;

        // Fix up the new record: parent, version.
        {
            let new_record = self.body.find_key_mut(&new_id).expect("just inserted");
            new_record.metadata.parent_key_id = Some(key_id.clone());
            new_record.metadata.version = old_version + 1;
        }

        // Retire the original, going through Rotating.
        //
        // The state machine allows Active -> Rotating -> Retired but
        // not Active -> Retired directly, because the intermediate
        // state is where a grace period would live once envelopes with
        // real deadlines exist. For now we pass through it and
        // immediately complete the rotation.
        {
            let old_record = self.body.find_key_mut(key_id).expect("checked above");
            let rotating = old_record
                .metadata
                .status
                .transition_to(KeyStatus::Rotating)
                .map_err(LifecycleError::from)?;
            let retired = rotating
                .transition_to(KeyStatus::Retired)
                .map_err(LifecycleError::from)?;
            old_record.metadata.status = retired;
        }

        Ok(new_id)
    }

    /// Revokes a key.
    ///
    /// The key material remains in the vault so that data protected
    /// while it was active can still be recovered, but the key is no
    /// longer trusted for new operations.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Lifecycle`] with
    /// [`LifecycleError::KeyNotFound`] if the key does not exist,
    /// [`LifecycleError::Terminal`] if the key is already `Destroyed`,
    /// or [`LifecycleError::Transition`] if the current status does not
    /// permit revocation.
    pub fn revoke_key(&mut self, key_id: &KeyId, _reason: RevokeReason) -> Result<(), VaultError> {
        self.require_writes_allowed()?;
        let record = self
            .body
            .find_key_mut(key_id)
            .ok_or_else(|| LifecycleError::KeyNotFound(key_id.clone()))?;

        if record.status() == KeyStatus::Destroyed {
            return Err(LifecycleError::Terminal {
                key_id: key_id.clone(),
                status: record.status(),
            }
            .into());
        }

        let new_status = record
            .metadata
            .status
            .transition_to(KeyStatus::Revoked)
            .map_err(LifecycleError::from)?;
        record.metadata.status = new_status;
        Ok(())
    }

    /// Destroys a key.
    ///
    /// The key material is dropped and the record moves to `Destroyed`.
    /// This is **irreversible**: data protected by this key becomes
    /// permanently unreadable.
    ///
    /// The caller must pass [`DestructionConfirmation::Explicit`] to
    /// acknowledge the irreversibility.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Lifecycle`] with
    /// [`LifecycleError::KeyNotFound`] if the key does not exist, or
    /// [`LifecycleError::Terminal`] if it is already destroyed.
    pub fn destroy_key(
        &mut self,
        key_id: &KeyId,
        _confirmation: DestructionConfirmation,
    ) -> Result<(), VaultError> {
        self.require_writes_allowed()?;
        let record = self
            .body
            .find_key_mut(key_id)
            .ok_or_else(|| LifecycleError::KeyNotFound(key_id.clone()))?;

        if record.status() == KeyStatus::Destroyed {
            return Err(LifecycleError::Terminal {
                key_id: key_id.clone(),
                status: KeyStatus::Destroyed,
            }
            .into());
        }

        // Drop the wrapped material by replacing it with an empty
        // variant of the same shape. The previous Vec is freed; if the
        // type gains a Drop impl with zeroization later, this will wipe
        // the bytes before release.
        let empty = match record.material {
            super::record::WrappedKeyMaterial::Symmetric(_) => {
                super::record::WrappedKeyMaterial::Symmetric(Vec::new())
            }
            super::record::WrappedKeyMaterial::Asymmetric(_) => {
                super::record::WrappedKeyMaterial::Asymmetric(Vec::new())
            }
            super::record::WrappedKeyMaterial::HardwareHandle(_) => {
                super::record::WrappedKeyMaterial::HardwareHandle(Vec::new())
            }
        };
        record.material = empty;

        record.metadata.status = KeyStatus::Destroyed;
        Ok(())
    }

    /// Internal helper: rejects operations when writes are not allowed.
    fn require_writes_allowed(&self) -> Result<(), VaultError> {
        if self.state.allows_writes() {
            Ok(())
        } else {
            Err(VaultError::StateDenied { state: self.state })
        }
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

/// Writes the vault to disk with crash-safe and durable semantics.
///
/// Steps:
///
/// 1. Serialize the file into memory.
/// 2. Create a uniquely named temp file in the same directory as the
///    target. Unique naming avoids collisions between concurrent writers.
/// 3. Write the whole payload and `fsync` the temp file, so its contents
///    are on stable storage before we publish it.
/// 4. `rename` the temp file onto the target. On POSIX this is atomic:
///    readers see either the old file or the new one, never a mix.
/// 5. `fsync` the containing directory, so the rename itself survives a
///    crash.
///
/// If any step fails, the original file (if it existed) is left intact.
/// Orphan temp files are harmless and can be removed manually; we do not
/// delete them automatically because a concurrent process might still
/// be writing to one.
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

    let tmp_path = unique_temp_path(path)?;

    // Write and fsync the temp file.
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(&out)?;
        f.sync_all()?;
    }

    // Rename onto the target. If this fails, try to clean up the temp.
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(VaultError::Io(e));
    }

    // fsync the directory so the rename is durable. Best-effort on
    // platforms that do not support directory fsync.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = fs::File::open(parent) {
                if let Err(e) = dir.sync_all() {
                    if e.kind() != std::io::ErrorKind::Unsupported {
                        return Err(VaultError::Io(e));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Builds a unique temp path next to `path`.
///
/// Format: `<name>.tmp.<8 hex chars>`. The suffix comes from the OS
/// CSPRNG so two writers cannot collide.
fn unique_temp_path(path: &Path) -> Result<PathBuf, VaultError> {
    let rng = OsRandomSource::new();
    let mut suffix = [0u8; 4];
    rng.fill_bytes(&mut suffix)?;

    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        ".tmp.{:02x}{:02x}{:02x}{:02x}",
        suffix[0], suffix[1], suffix[2], suffix[3]
    ));

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(name))
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

fn generate_vault_id<S: RandomSource>(source: &S) -> Result<String, VaultError> {
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
// Real, algorithm-specific key material. For Ed25519 we draw a signing
// key and keep its 32-byte seed. For ML-KEM we draw a hybrid key pair
// and keep the secret half. For the AEAD algorithms we draw 32 random
// bytes. Everything is returned in a Zeroizing buffer so the caller
// does not have to remember to wipe it.

/// Secret material plus, optionally, its public half.
type GeneratedMaterial = (Zeroizing<Vec<u8>>, Option<Vec<u8>>);

fn generate_material<S: RandomSource>(
    algorithm: Algorithm,
    source: &S,
) -> Result<GeneratedMaterial, VaultError> {
    let result = match algorithm {
        Algorithm::Ed25519 => {
            let pair = crate::crypto::sign::generate();
            let secret = Zeroizing::new(pair.signing.to_bytes().to_vec());
            let public = pair.verifying.to_bytes().to_vec();
            (secret, Some(public))
        }
        Algorithm::MlKem768 => {
            let pair = crate::crypto::kem::hybrid::generate();
            let secret = pair.secret_key_bytes();
            let public = pair.public_key_bytes();
            (secret, Some(public))
        }
        Algorithm::Aes256Gcm | Algorithm::ChaCha20Poly1305 => {
            let mut buf = Zeroizing::new(vec![0u8; 32]);
            source.fill_bytes(buf.as_mut())?;
            (buf, None)
        }
    };
    Ok(result)
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

    #[test]
    fn session_starts_unlocked() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        assert_eq!(session.state(), VaultState::Unlocked);
    }

    #[test]
    fn sealed_session_refuses_writes_but_allows_reads() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        session.seal().unwrap();
        assert_eq!(session.state(), VaultState::Sealed);

        // Reads still work.
        assert_eq!(session.key_count(), 0);

        // Writes are refused.
        let err = session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap_err();
        assert!(matches!(err, VaultError::StateDenied { .. }));
    }

    #[test]
    fn unseal_restores_write_access() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        session.seal().unwrap();
        session.unseal().unwrap();
        assert_eq!(session.state(), VaultState::Unlocked);

        session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();
        assert_eq!(session.key_count(), 1);
    }

    #[test]
    fn compromised_session_refuses_everything() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        session.mark_compromised().unwrap();
        assert_eq!(session.state(), VaultState::Compromised);

        // Writes refused.
        assert!(matches!(
            session.generate_key(Algorithm::Ed25519, Purpose::Sign),
            Err(VaultError::StateDenied { .. })
        ));

        // Sealing refused (state transition invalid).
        assert!(matches!(
            session.seal(),
            Err(VaultError::StateTransition(_))
        ));

        // Unsealing refused.
        assert!(matches!(
            session.unseal(),
            Err(VaultError::StateTransition(_))
        ));
    }

    #[test]
    fn find_key_mut_requires_write_access() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();

        session.seal().unwrap();
        let err = session.find_key_mut(&id).unwrap_err();
        assert!(matches!(err, VaultError::StateDenied { .. }));

        session.unseal().unwrap();
        let record = session.find_key_mut(&id).unwrap().unwrap();
        record.metadata.status = KeyStatus::Active;
        assert_eq!(session.find_key(&id).unwrap().status(), KeyStatus::Active);
    }

    #[test]
    fn no_temp_files_remain_after_success() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();

        // The directory should contain exactly the vault file.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "test.nqv");
    }

    #[test]
    fn temp_path_is_unique_per_call() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "x.nqv");
        let a = unique_temp_path(&path).unwrap();
        let b = unique_temp_path(&path).unwrap();
        assert_ne!(a, b);
        // Both live in the same parent.
        assert_eq!(a.parent(), path.parent());
        assert_eq!(b.parent(), path.parent());
    }

    #[test]
    fn temp_path_keeps_original_extension_visible() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "vault.nqv");
        let tmp = unique_temp_path(&path).unwrap();
        let name = tmp.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("vault.nqv.tmp."));
    }

    // =========================================================================
    // Lifecycle tests
    // =========================================================================

    fn make_active(session: &mut Session) -> KeyId {
        let id = session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();
        session.activate_key(&id).unwrap();
        id
    }

    #[test]
    fn activate_key_moves_generated_to_active() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();
        assert_eq!(
            session.find_key(&id).unwrap().status(),
            KeyStatus::Generated
        );

        session.activate_key(&id).unwrap();
        assert_eq!(session.find_key(&id).unwrap().status(), KeyStatus::Active);
    }

    #[test]
    fn activate_key_rejects_unknown_id() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let rng = OsRandomSource::new();
        let bogus = KeyId::generate(&rng, "ed25519").unwrap();
        let err = session.activate_key(&bogus).unwrap_err();
        assert!(matches!(err, VaultError::Lifecycle(_)));
    }

    #[test]
    fn activate_key_rejects_already_active() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active(&mut session);
        let err = session.activate_key(&id).unwrap_err();
        assert!(matches!(err, VaultError::Lifecycle(_)));
    }

    #[test]
    fn rotate_key_creates_replacement_and_retires_original() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let old = make_active(&mut session);
        let old_version = session.find_key(&old).unwrap().metadata.version;

        let new = session.rotate_key(&old).unwrap();
        assert_ne!(old, new);
        assert_eq!(session.key_count(), 2);

        // Original retired.
        let old_rec = session.find_key(&old).unwrap();
        assert_eq!(old_rec.status(), KeyStatus::Retired);

        // Replacement carries parent and bumped version.
        let new_rec = session.find_key(&new).unwrap();
        assert_eq!(new_rec.metadata.parent_key_id.as_ref(), Some(&old));
        assert_eq!(new_rec.metadata.version, old_version + 1);
        assert_eq!(new_rec.algorithm(), Algorithm::Ed25519);
        assert_eq!(new_rec.purpose(), Purpose::Sign);
    }

    #[test]
    fn rotate_key_rejects_non_active() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session
            .generate_key(Algorithm::Ed25519, Purpose::Sign)
            .unwrap();
        // Still in Generated, not Active.
        let err = session.rotate_key(&id).unwrap_err();
        assert!(matches!(err, VaultError::Lifecycle(_)));
    }

    #[test]
    fn revoke_key_moves_active_to_revoked() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active(&mut session);
        session.revoke_key(&id, RevokeReason::Compromised).unwrap();
        assert_eq!(session.find_key(&id).unwrap().status(), KeyStatus::Revoked);
    }

    #[test]
    fn revoke_key_rejects_destroyed() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active(&mut session);
        session
            .destroy_key(&id, DestructionConfirmation::Explicit)
            .unwrap();
        let err = session
            .revoke_key(&id, RevokeReason::Compromised)
            .unwrap_err();
        assert!(matches!(err, VaultError::Lifecycle(_)));
    }

    #[test]
    fn destroy_key_clears_material_and_marks_destroyed() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active(&mut session);
        let material_len_before = session.find_key(&id).unwrap().material.len();
        assert!(material_len_before > 0);

        session
            .destroy_key(&id, DestructionConfirmation::Explicit)
            .unwrap();

        let record = session.find_key(&id).unwrap();
        assert_eq!(record.status(), KeyStatus::Destroyed);
        assert_eq!(record.material.len(), 0);
        assert!(record.material.is_empty());
    }

    #[test]
    fn destroy_key_is_irreversible() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active(&mut session);
        session
            .destroy_key(&id, DestructionConfirmation::Explicit)
            .unwrap();

        // Destroying again fails.
        let err = session
            .destroy_key(&id, DestructionConfirmation::Explicit)
            .unwrap_err();
        assert!(matches!(err, VaultError::Lifecycle(_)));

        // Cannot activate either.
        let err = session.activate_key(&id).unwrap_err();
        assert!(matches!(err, VaultError::Lifecycle(_)));
    }

    #[test]
    fn lifecycle_operations_respect_vault_state() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active(&mut session);
        session.seal().unwrap();

        // All mutations denied in sealed state.
        assert!(matches!(
            session.activate_key(&id),
            Err(VaultError::StateDenied { .. })
        ));
        assert!(matches!(
            session.rotate_key(&id),
            Err(VaultError::StateDenied { .. })
        ));
        assert!(matches!(
            session.revoke_key(&id, RevokeReason::Compromised),
            Err(VaultError::StateDenied { .. })
        ));
        assert!(matches!(
            session.destroy_key(&id, DestructionConfirmation::Explicit),
            Err(VaultError::StateDenied { .. })
        ));
    }

    #[test]
    fn lifecycle_changes_persist_across_lock_and_unlock() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();

        let (active_id, destroyed_id) = {
            let vault = Vault::open(&path).unwrap();
            let mut session = vault.unlock(b"pw").unwrap();

            let a = make_active(&mut session);
            let d = session
                .generate_key(Algorithm::Ed25519, Purpose::Sign)
                .unwrap();
            session
                .destroy_key(&d, DestructionConfirmation::Explicit)
                .unwrap();

            session.lock().unwrap();
            (a, d)
        };

        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        assert_eq!(
            session.find_key(&active_id).unwrap().status(),
            KeyStatus::Active
        );
        assert_eq!(
            session.find_key(&destroyed_id).unwrap().status(),
            KeyStatus::Destroyed
        );
    }

    // =========================================================================
    // Envelope integration tests
    // =========================================================================

    fn make_active_aead_key(session: &mut Session) -> KeyId {
        let id = session
            .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
            .unwrap();
        session.activate_key(&id).unwrap();
        id
    }

    #[test]
    fn session_encrypt_decrypt_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active_aead_key(&mut session);
        let plaintext = b"the secret message";
        let env_bytes = session
            .encrypt(&id, plaintext, b"note.txt".to_vec())
            .unwrap();

        let recovered = session.decrypt(&env_bytes).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn session_encrypt_rejects_inactive_key() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session
            .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
            .unwrap();
        // Not activated.
        let err = session.encrypt(&id, b"data", Vec::new()).unwrap_err();
        assert!(matches!(err, VaultError::Envelope(_)));
    }

    #[test]
    fn session_encrypt_rejects_unknown_key() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();

        let rng = OsRandomSource::new();
        let bogus = KeyId::generate(&rng, "aes256gcm").unwrap();
        let err = session.encrypt(&bogus, b"data", Vec::new()).unwrap_err();
        assert!(matches!(err, VaultError::Lifecycle(_)));
    }

    #[test]
    fn session_decrypt_rejects_tampered_envelope() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active_aead_key(&mut session);
        let mut env_bytes = session.encrypt(&id, b"payload", Vec::new()).unwrap();
        let last = env_bytes.len() - 1;
        env_bytes[last] ^= 0x01;

        let err = session.decrypt(&env_bytes).unwrap_err();
        assert!(matches!(err, VaultError::Envelope(_)));
    }

    #[test]
    fn session_envelope_operations_denied_when_sealed() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active_aead_key(&mut session);
        let env_bytes = session.encrypt(&id, b"payload", Vec::new()).unwrap();

        session.seal().unwrap();

        // Encrypt and decrypt are both denied in the sealed state.
        assert!(matches!(
            session.encrypt(&id, b"more", Vec::new()),
            Err(VaultError::StateDenied { .. })
        ));
        assert!(matches!(
            session.decrypt(&env_bytes),
            Err(VaultError::StateDenied { .. })
        ));
    }

    #[test]
    fn session_envelope_operations_denied_when_compromised() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active_aead_key(&mut session);
        session.mark_compromised().unwrap();

        assert!(matches!(
            session.encrypt(&id, b"data", Vec::new()),
            Err(VaultError::StateDenied { .. })
        ));
    }

    #[test]
    fn session_file_roundtrip() {
        use std::fs;

        let dir = TempDir::new().unwrap();
        let vault_path = temp_path(&dir, "test.nqv");
        Vault::create(&vault_path, b"pw", None).unwrap();
        let vault = Vault::open(&vault_path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = make_active_aead_key(&mut session);

        let input = dir.path().join("letter.txt");
        let output = dir.path().join("letter-recovered.txt");
        fs::write(&input, b"dear friend, ...").unwrap();

        let encrypted_path = session
            .encrypt_file(&input, &id, b"letter.txt".to_vec())
            .unwrap();
        assert!(encrypted_path.exists());

        session.decrypt_file(&encrypted_path, &output).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"dear friend, ...");
    }

    #[test]
    fn session_envelope_survives_lock_and_unlock() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();

        let (id, env_bytes) = {
            let vault = Vault::open(&path).unwrap();
            let mut session = vault.unlock(b"pw").unwrap();
            let id = make_active_aead_key(&mut session);
            let bytes = session.encrypt(&id, b"persistent", Vec::new()).unwrap();
            session.lock().unwrap();
            (id, bytes)
        };

        // Reopen and decrypt.
        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        let _ = id;
        let recovered = session.decrypt(&env_bytes).unwrap();
        assert_eq!(recovered.as_slice(), b"persistent");
    }

    // =========================================================================
    // Identity integration tests
    // =========================================================================

    #[test]
    fn create_identity_stores_identity_and_signing_key() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(Some("alice".to_string())).unwrap();
        assert_eq!(session.identity_count(), 1);
        assert_eq!(session.key_count(), 1);

        let identity = session.find_identity(&id).unwrap();
        assert_eq!(identity.metadata.label.as_deref(), Some("alice"));
        assert_eq!(identity.metadata.status, IdentityStatus::Active);
        assert_eq!(identity.metadata.version, 1);

        // The signing key exists, is Active, and is Ed25519/Sign.
        let key = session.find_key(&identity.signing_key).unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert_eq!(key.purpose(), Purpose::Sign);
        assert_eq!(key.status(), KeyStatus::Active);
    }

    #[test]
    fn create_identity_without_label() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let identity = session.find_identity(&id).unwrap();
        assert!(identity.metadata.label.is_none());
    }

    #[test]
    fn identities_have_distinct_ids() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let a = session.create_identity(None).unwrap();
        let b = session.create_identity(None).unwrap();
        assert_ne!(a, b);
        assert_eq!(session.identity_count(), 2);
        assert_eq!(session.key_count(), 2);
    }

    #[test]
    fn list_identities_returns_all() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        session.create_identity(None).unwrap();
        session.create_identity(None).unwrap();
        session.create_identity(None).unwrap();

        let ids: Vec<_> = session.list_identities().map(|i| i.id.clone()).collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn create_identity_requires_write_access() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        session.seal().unwrap();
        let err = session.create_identity(None).unwrap_err();
        assert!(matches!(err, VaultError::StateDenied { .. }));
    }

    #[test]
    fn identities_persist_across_lock_and_unlock() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();

        let id = {
            let vault = Vault::open(&path).unwrap();
            let mut session = vault.unlock(b"pw").unwrap();
            let id = session
                .create_identity(Some("persistent".to_string()))
                .unwrap();
            session.lock().unwrap();
            id
        };

        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        assert_eq!(session.identity_count(), 1);
        let identity = session.find_identity(&id).unwrap();
        assert_eq!(identity.metadata.label.as_deref(), Some("persistent"));
    }

    #[test]
    fn find_identity_mut_requires_write_access() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        session.seal().unwrap();

        let err = session.find_identity_mut(&id).unwrap_err();
        assert!(matches!(err, VaultError::StateDenied { .. }));

        session.unseal().unwrap();
        let identity = session.find_identity_mut(&id).unwrap().unwrap();
        identity.metadata.label = Some("updated".to_string());
        assert_eq!(
            session
                .find_identity(&id)
                .unwrap()
                .metadata
                .label
                .as_deref(),
            Some("updated")
        );
    }

    // =========================================================================
    // Identity signing tests
    // =========================================================================

    #[test]
    fn identity_sign_and_verify_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let message = b"the document to sign";
        let sig = session.identity_sign(&id, message).unwrap();
        session.identity_verify(&id, message, &sig).unwrap();
    }

    #[test]
    fn identity_verify_rejects_wrong_message() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let sig = session.identity_sign(&id, b"original").unwrap();
        let err = session.identity_verify(&id, b"tampered", &sig).unwrap_err();
        assert!(matches!(err, VaultError::Signature(_)));
    }

    #[test]
    fn identity_verify_rejects_tampered_signature() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let msg = b"message";
        let sig = session.identity_sign(&id, msg).unwrap();
        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes[0] ^= 0x01;
        let bad_sig = Signature::from_bytes(&sig_bytes).unwrap();

        let err = session.identity_verify(&id, msg, &bad_sig).unwrap_err();
        assert!(matches!(err, VaultError::Signature(_)));
    }

    #[test]
    fn identity_verify_rejects_signature_from_other_identity() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let alice = session.create_identity(Some("alice".to_string())).unwrap();
        let bob = session.create_identity(Some("bob".to_string())).unwrap();

        let msg = b"signed by alice";
        let sig = session.identity_sign(&alice, msg).unwrap();

        // Verifying with Bob's identity should fail.
        let err = session.identity_verify(&bob, msg, &sig).unwrap_err();
        assert!(matches!(err, VaultError::Signature(_)));
    }

    #[test]
    fn identity_sign_rejects_unknown_identity() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();

        let rng = OsRandomSource::new();
        let bogus = IdentityId::generate(&rng).unwrap();
        let err = session.identity_sign(&bogus, b"data").unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotFound(_)));
    }

    #[test]
    fn identity_sign_rejects_revoked_identity() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();

        // Manually flip to Revoked (revocation API lands in NQ-006-06).
        {
            let identity = session.find_identity_mut(&id).unwrap().unwrap();
            identity.metadata.status = IdentityStatus::Revoked;
            identity.metadata.revoked_at = Some(Timestamp::from_secs(1_800_000_000));
        }

        let err = session.identity_sign(&id, b"data").unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotUsable { .. }));
    }

    #[test]
    fn identity_verify_works_on_revoked_identity_for_past_signatures() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let msg = b"signed before revocation";
        let sig = session.identity_sign(&id, msg).unwrap();

        // Revoke the identity.
        {
            let identity = session.find_identity_mut(&id).unwrap().unwrap();
            identity.metadata.status = IdentityStatus::Revoked;
            identity.metadata.revoked_at = Some(Timestamp::from_secs(1_800_000_000));
            identity.metadata.revocation_reason =
                Some(crate::vault::lifecycle::RevokeReason::Compromised);
        }

        // Verification still works: the public key is available.
        session.identity_verify(&id, msg, &sig).unwrap();
    }

    #[test]
    fn identity_signatures_survive_lock_and_unlock() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();

        let (id, msg, sig) = {
            let vault = Vault::open(&path).unwrap();
            let mut session = vault.unlock(b"pw").unwrap();
            let id = session.create_identity(None).unwrap();
            let msg = b"persistent message".to_vec();
            let sig = session.identity_sign(&id, &msg).unwrap();
            session.lock().unwrap();
            (id, msg, sig)
        };

        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        session.identity_verify(&id, &msg, &sig).unwrap();
    }

    #[test]
    fn signing_key_record_has_public_half() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let identity = session.find_identity(&id).unwrap();
        let record = session.find_key(&identity.signing_key).unwrap();
        let pk = record
            .public_key_bytes()
            .expect("Ed25519 has a public half");
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn symmetric_keys_have_no_public_half() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let key_id = session
            .generate_key(Algorithm::Aes256Gcm, Purpose::Encrypt)
            .unwrap();
        let record = session.find_key(&key_id).unwrap();
        assert!(record.public_key_bytes().is_none());
    }

    // =========================================================================
    // Identity rotation tests
    // =========================================================================

    #[test]
    fn rotate_identity_swaps_signing_key_and_bumps_version() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let old_key = session.find_identity(&id).unwrap().signing_key.clone();
        let old_version = session.find_identity(&id).unwrap().metadata.version;

        let new_key = session.rotate_identity_key(&id).unwrap();

        assert_ne!(old_key, new_key);
        let identity = session.find_identity(&id).unwrap();
        assert_eq!(identity.signing_key, new_key);
        assert_eq!(identity.metadata.version, old_version + 1);
        assert_eq!(identity.metadata.status, IdentityStatus::Active);

        // Old key retired, new key active.
        assert_eq!(
            session.find_key(&old_key).unwrap().status(),
            KeyStatus::Retired
        );
        assert_eq!(
            session.find_key(&new_key).unwrap().status(),
            KeyStatus::Active
        );
    }

    #[test]
    fn rotate_identity_keeps_identity_id() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        session.rotate_identity_key(&id).unwrap();

        // The identity is still discoverable under the same id.
        assert!(session.find_identity(&id).is_some());
        assert_eq!(session.identity_count(), 1);
    }

    #[test]
    fn new_signing_key_signs_and_verifies_after_rotation() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        session.rotate_identity_key(&id).unwrap();

        let msg = b"signed after rotation";
        let sig = session.identity_sign(&id, msg).unwrap();
        session.identity_verify(&id, msg, &sig).unwrap();
    }

    #[test]
    fn old_signatures_verify_after_rotation() {
        // A signature made with the old key must still verify
        // afterwards, because the public half of the retired key is
        // still in the vault. We assert this by capturing the old
        // public key before rotating, then checking it still verifies
        // the old signature.
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let msg = b"signed before rotation";
        let old_sig = session.identity_sign(&id, msg).unwrap();

        // Capture the old key id and its public half for later.
        let old_signing_key = session.find_identity(&id).unwrap().signing_key.clone();
        let old_pk = session
            .find_key(&old_signing_key)
            .unwrap()
            .public_key_bytes()
            .unwrap()
            .to_vec();

        session.rotate_identity_key(&id).unwrap();

        // The old key is Retired but its public half survives.
        let record = session.find_key(&old_signing_key).unwrap();
        assert_eq!(record.status(), KeyStatus::Retired);
        assert_eq!(record.public_key_bytes().unwrap(), old_pk.as_slice());

        // The old signature verifies against the old public key.
        let vk = sign::VerifyingKey::from_bytes(&old_pk).unwrap();
        vk.verify(msg, &old_sig).unwrap();
    }

    #[test]
    fn rotate_rejects_unknown_identity() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let rng = OsRandomSource::new();
        let bogus = IdentityId::generate(&rng).unwrap();
        let err = session.rotate_identity_key(&bogus).unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotFound(_)));
    }

    #[test]
    fn rotate_rejects_revoked_identity() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        {
            let identity = session.find_identity_mut(&id).unwrap().unwrap();
            identity.metadata.status = IdentityStatus::Revoked;
            identity.metadata.revoked_at = Some(Timestamp::from_secs(1_800_000_000));
        }

        let err = session.rotate_identity_key(&id).unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotUsable { .. }));
    }

    #[test]
    fn rotate_requires_write_access() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        session.seal().unwrap();

        let err = session.rotate_identity_key(&id).unwrap_err();
        assert!(matches!(err, VaultError::StateDenied { .. }));
    }

    #[test]
    fn multiple_rotations_increment_version_monotonically() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        assert_eq!(session.find_identity(&id).unwrap().metadata.version, 1);

        session.rotate_identity_key(&id).unwrap();
        assert_eq!(session.find_identity(&id).unwrap().metadata.version, 2);

        session.rotate_identity_key(&id).unwrap();
        assert_eq!(session.find_identity(&id).unwrap().metadata.version, 3);

        // Every rotation adds a new key; none is deleted.
        assert_eq!(session.key_count(), 3);
        assert_eq!(session.identity_count(), 1);
    }

    // =========================================================================
    // Identity revocation tests
    // =========================================================================

    #[test]
    fn revoke_identity_sets_status_and_metadata() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        session
            .revoke_identity(&id, RevokeReason::Compromised)
            .unwrap();

        let identity = session.find_identity(&id).unwrap();
        assert_eq!(identity.metadata.status, IdentityStatus::Revoked);
        assert!(identity.metadata.revoked_at.is_some());
        assert!(matches!(
            identity.metadata.revocation_reason,
            Some(RevokeReason::Compromised)
        ));
        assert!(identity.is_revoked());
        assert!(!identity.is_active());
    }

    #[test]
    fn revoke_identity_blocks_future_signatures() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        session
            .revoke_identity(&id, RevokeReason::OwnerLeft)
            .unwrap();

        let err = session.identity_sign(&id, b"data").unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotUsable { .. }));
    }

    #[test]
    fn revoke_identity_keeps_past_signatures_verifiable() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let msg = b"signed before revocation";
        let sig = session.identity_sign(&id, msg).unwrap();

        session
            .revoke_identity(&id, RevokeReason::Superseded)
            .unwrap();

        // Verification still succeeds.
        session.identity_verify(&id, msg, &sig).unwrap();
    }

    #[test]
    fn revoke_identity_is_idempotent_error() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        session
            .revoke_identity(&id, RevokeReason::Compromised)
            .unwrap();

        let err = session
            .revoke_identity(&id, RevokeReason::Compromised)
            .unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotUsable { .. }));
    }

    #[test]
    fn revoke_rejects_unknown_identity() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let rng = OsRandomSource::new();
        let bogus = IdentityId::generate(&rng).unwrap();
        let err = session
            .revoke_identity(&bogus, RevokeReason::Compromised)
            .unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotFound(_)));
    }

    #[test]
    fn revoked_identity_cannot_be_rotated() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        session
            .revoke_identity(&id, RevokeReason::Compromised)
            .unwrap();

        let err = session.rotate_identity_key(&id).unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotUsable { .. }));
    }

    #[test]
    fn revoke_identity_requires_write_access() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        session.seal().unwrap();

        let err = session
            .revoke_identity(&id, RevokeReason::Compromised)
            .unwrap_err();
        assert!(matches!(err, VaultError::StateDenied { .. }));
    }

    #[test]
    fn revoke_identity_persists_across_lock_and_unlock() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();

        let id = {
            let vault = Vault::open(&path).unwrap();
            let mut session = vault.unlock(b"pw").unwrap();
            let id = session.create_identity(None).unwrap();
            session
                .revoke_identity(&id, RevokeReason::OwnerLeft)
                .unwrap();
            session.lock().unwrap();
            id
        };

        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        let identity = session.find_identity(&id).unwrap();
        assert!(identity.is_revoked());
        assert!(matches!(
            identity.metadata.revocation_reason,
            Some(RevokeReason::OwnerLeft)
        ));
    }

    #[test]
    fn revoke_identity_does_not_touch_signing_key() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let id = session.create_identity(None).unwrap();
        let signing_key = session.find_identity(&id).unwrap().signing_key.clone();

        session
            .revoke_identity(&id, RevokeReason::Compromised)
            .unwrap();

        // The signing key status is unchanged.
        assert_eq!(
            session.find_key(&signing_key).unwrap().status(),
            KeyStatus::Active
        );
    }

    // =========================================================================
    // Credential tests
    // =========================================================================

    #[test]
    fn issue_and_verify_credential_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let alice = session.create_identity(Some("alice".to_string())).unwrap();
        let bob = session.create_identity(Some("bob".to_string())).unwrap();

        let claims = b"role=admin".to_vec();
        let expires = Some(Timestamp::from_secs(9_999_999_999));
        let cred_bytes = session
            .issue_credential(&alice, bob.clone(), claims.clone(), expires)
            .unwrap();

        let cred = session.verify_credential(&cred_bytes).unwrap();
        assert_eq!(cred.issuer, alice);
        assert_eq!(cred.subject, bob);
        assert_eq!(cred.claims(), claims.as_slice());
        assert_eq!(cred.expires_at, expires);
    }

    #[test]
    fn credential_without_expiry_verifies() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let issuer = session.create_identity(None).unwrap();
        let subject = session.create_identity(None).unwrap();

        let cred_bytes = session
            .issue_credential(&issuer, subject, b"permanent".to_vec(), None)
            .unwrap();
        let cred = session.verify_credential(&cred_bytes).unwrap();
        assert!(cred.expires_at.is_none());
    }

    #[test]
    fn verify_credential_rejects_tampered_claims() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let issuer = session.create_identity(None).unwrap();
        let subject = session.create_identity(None).unwrap();

        let cred_bytes = session
            .issue_credential(&issuer, subject, b"role=user".to_vec(), None)
            .unwrap();

        // Tamper the credential in transit.
        let mut cred: Credential = crate::vault::from_slice(&cred_bytes).unwrap();
        cred.claims = b"role=admin".to_vec();
        let tampered = crate::vault::to_vec(&cred).unwrap();

        let err = session.verify_credential(&tampered).unwrap_err();
        assert!(matches!(err, VaultError::Credential(_)));
    }

    #[test]
    fn issue_credential_rejects_unknown_issuer() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let subject = session.create_identity(None).unwrap();
        let rng = OsRandomSource::new();
        let bogus = IdentityId::generate(&rng).unwrap();

        let err = session
            .issue_credential(&bogus, subject, b"claims".to_vec(), None)
            .unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotFound(_)));
    }

    #[test]
    fn issue_credential_rejects_revoked_issuer() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let issuer = session.create_identity(None).unwrap();
        let subject = session.create_identity(None).unwrap();

        session
            .revoke_identity(&issuer, RevokeReason::Compromised)
            .unwrap();

        let err = session
            .issue_credential(&issuer, subject, b"claims".to_vec(), None)
            .unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotUsable { .. }));
    }

    #[test]
    fn verify_credential_rejects_unknown_issuer() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();

        // Issue a credential in one vault.
        let cred_bytes = {
            let vault = Vault::open(&path).unwrap();
            let mut session = vault.unlock(b"pw").unwrap();
            let issuer = session.create_identity(None).unwrap();
            let subject = session.create_identity(None).unwrap();
            session
                .issue_credential(&issuer, subject, b"claims".to_vec(), None)
                .unwrap()
        };

        // Wipe and recreate the vault: different identities, so the
        // credential's issuer is unknown.
        std::fs::remove_file(&path).unwrap();
        Vault::create(&path, b"pw", None).unwrap();

        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        let err = session.verify_credential(&cred_bytes).unwrap_err();
        assert!(matches!(err, VaultError::IdentityNotFound(_)));
    }

    #[test]
    fn verify_credential_succeeds_after_issuer_rotation() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let issuer = session.create_identity(None).unwrap();
        let subject = session.create_identity(None).unwrap();

        let cred_bytes = session
            .issue_credential(&issuer, subject, b"claims".to_vec(), None)
            .unwrap();

        // Rotate the issuer's signing key. The credential was signed
        // by the old key. Since the identity now points to the new key,
        // verifying through the session would fail (correctly, the
        // credential is no longer signed by the current key). We assert
        // that by using verify_with_key with the old public key.
        let old_signing_key = session.find_identity(&issuer).unwrap().signing_key.clone();
        let old_pk = session
            .find_key(&old_signing_key)
            .unwrap()
            .public_key_bytes()
            .unwrap()
            .to_vec();

        session.rotate_identity_key(&issuer).unwrap();

        // The credential still verifies against the old public key.
        let vk = sign::VerifyingKey::from_bytes(&old_pk).unwrap();
        let cred = Credential::verify_with_key(&cred_bytes, &vk).unwrap();
        assert_eq!(cred.issuer, issuer);

        // But the session's verification now fails, because the
        // identity's current key is the new one.
        let err = session.verify_credential(&cred_bytes).unwrap_err();
        assert!(matches!(err, VaultError::Credential(_)));
    }

    #[test]
    fn verify_credential_succeeds_after_issuer_revocation() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let issuer = session.create_identity(None).unwrap();
        let subject = session.create_identity(None).unwrap();

        let cred_bytes = session
            .issue_credential(&issuer, subject, b"claims".to_vec(), None)
            .unwrap();

        session
            .revoke_identity(&issuer, RevokeReason::Superseded)
            .unwrap();

        // The signing key is untouched by revocation, so verification
        // still succeeds. Whether a real deployment should refuse
        // credentials from revoked issuers is a policy decision
        // (Phase 11).
        let cred = session.verify_credential(&cred_bytes).unwrap();
        assert_eq!(cred.issuer, issuer);
    }

    #[test]
    fn issue_credential_requires_write_access() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();
        let vault = Vault::open(&path).unwrap();
        let mut session = vault.unlock(b"pw").unwrap();

        let issuer = session.create_identity(None).unwrap();
        let subject = session.create_identity(None).unwrap();

        session.seal().unwrap();

        let err = session
            .issue_credential(&issuer, subject, b"claims".to_vec(), None)
            .unwrap_err();
        assert!(matches!(err, VaultError::StateDenied { .. }));
    }

    #[test]
    fn multiple_writes_leave_only_the_vault_file() {
        let dir = TempDir::new().unwrap();
        let path = temp_path(&dir, "test.nqv");
        Vault::create(&path, b"pw", None).unwrap();

        // Modify and re-lock a few times.
        for i in 0..3 {
            let vault = Vault::open(&path).unwrap();
            let mut session = vault.unlock(b"pw").unwrap();
            session.body_mut().metadata.label = Some(format!("run-{i}"));
            session.lock().unwrap();
        }

        // Still exactly one file.
        let count = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 1);

        // And the latest label persisted.
        let vault = Vault::open(&path).unwrap();
        let session = vault.unlock(b"pw").unwrap();
        assert_eq!(session.body().metadata.label.as_deref(), Some("run-2"));
    }
}

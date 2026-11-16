use std::{
    fmt,
    sync::{Arc, Mutex},
};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error as CryptokiError, RvError},
    mechanism::{
        Mechanism,
        aead::GcmParams,
        dsa::{HedgeType, SignAdditionalContext},
    },
    object::{Attribute, AttributeType, KeyType, MlDsaParameterSetType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use getrandom::fill;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::HsmError;

/// Opaque reference to a token-resident ML-DSA-65 key pair. It contains public metadata only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pkcs11KeyRef {
    id: Vec<u8>,
    label: String,
    token_label: String,
    token_serial: String,
    public_key: Vec<u8>,
}
impl Pkcs11KeyRef {
    /// Human-readable HSM object label.
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Token label the key reference is bound to.
    pub fn token_label(&self) -> &str {
        &self.token_label
    }
    /// Token serial number used to prevent a key reference being replayed against another token.
    pub fn token_serial(&self) -> &str {
        &self.token_serial
    }
    /// Raw ML-DSA-65 public key bytes; private key bytes are never included.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
    /// Stable PKCS#11 CKA_ID used to re-find the key in a later session.
    pub fn key_id(&self) -> &[u8] {
        &self.id
    }
}
impl fmt::Debug for Pkcs11KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11KeyRef")
            .field("id", &"[redacted]")
            .field("label", &self.label)
            .field("token_label", &self.token_label)
            .field("public_key_bytes", &self.public_key.len())
            .finish()
    }
}

/// PKCS#11 provider configured for one token and a protected user PIN.
pub struct Pkcs11Provider {
    context: Pkcs11,
    slot: Slot,
    pin: Zeroizing<String>,
    token_label: String,
    token_serial: String,
    login_initialized: Mutex<bool>,
}
impl fmt::Debug for Pkcs11Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Provider")
            .field("slot", &self.slot)
            .field("token_label", &self.token_label)
            .field("pin", &"[redacted]")
            .finish()
    }
}
impl Pkcs11Provider {
    /// Load and initialize a PKCS#11 module, selecting the `slot_index`-th slot containing a token.
    /// Supply the PIN from a secret manager; it is never included in logs or Debug output.
    pub fn connect(
        module_path: impl AsRef<str>,
        slot_index: usize,
        pin: impl Into<String>,
    ) -> Result<Arc<Self>, HsmError> {
        let context =
            Pkcs11::new(module_path.as_ref()).map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let slots = context
            .get_slots_with_token()
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let slot = *slots.get(slot_index).ok_or(HsmError::InvalidConfig)?;
        let token_info = context
            .get_token_info(slot)
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let token_label = token_info.label().trim().to_owned();
        let token_serial = token_info.serial_number().trim().to_owned();
        let pin = pin.into();
        if token_label.is_empty() || token_serial.is_empty() || pin.is_empty() {
            return Err(HsmError::InvalidConfig);
        }
        let provider = Arc::new(Self {
            context,
            slot,
            pin: Zeroizing::new(pin),
            token_label,
            token_serial,
            login_initialized: Mutex::new(false),
        });
        // Authenticate once during initialization so configuration failures surface early.
        let _session = provider.open_session()?;
        Ok(provider)
    }

    /// Connect by token serial number, which is more stable than a slot index when multiple tokens exist.
    pub fn connect_by_token_serial(
        module_path: impl AsRef<str>,
        wanted_serial: &str,
        pin: impl Into<String>,
    ) -> Result<Arc<Self>, HsmError> {
        if wanted_serial.trim().is_empty() {
            return Err(HsmError::InvalidConfig);
        }
        let context =
            Pkcs11::new(module_path.as_ref()).map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let slots = context
            .get_slots_with_token()
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let mut matched = None;
        for slot in slots {
            let info = context
                .get_token_info(slot)
                .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
            if info.serial_number().trim() == wanted_serial.trim() {
                if matched.is_some() {
                    return Err(HsmError::InvalidConfig);
                }
                matched = Some(slot);
            }
        }
        let slot = matched.ok_or(HsmError::InvalidConfig)?;
        let info = context
            .get_token_info(slot)
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let token_label = info.label().trim().to_owned();
        let token_serial = info.serial_number().trim().to_owned();
        let pin = pin.into();
        if token_label.is_empty() || token_serial.is_empty() || pin.is_empty() {
            return Err(HsmError::InvalidConfig);
        }
        let provider = Arc::new(Self {
            context,
            slot,
            pin: Zeroizing::new(pin),
            token_label,
            token_serial,
            login_initialized: Mutex::new(false),
        });
        let _session = provider.open_session()?;
        Ok(provider)
    }

    fn open_session(&self) -> Result<Session, HsmError> {
        let session = self
            .context
            .open_rw_session(self.slot)
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let mut login_initialized = self
            .login_initialized
            .lock()
            .map_err(|_| HsmError::InvalidConfig)?;
        if !*login_initialized {
            let pin = AuthPin::new(self.pin.as_str().to_owned().into());
            session
                .login(UserType::User, Some(&pin))
                .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
            *login_initialized = true;
        }
        Ok(session)
    }

    fn find_key(
        &self,
        session: &Session,
        id: &[u8],
        class: ObjectClass,
    ) -> Result<ObjectHandle, HsmError> {
        let template = [
            Attribute::Class(class),
            Attribute::KeyType(KeyType::ML_DSA),
            Attribute::Id(id.to_vec()),
        ];
        let mut found = session
            .find_objects(&template)
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        match found.len() {
            0 => Err(HsmError::KeyNotFound),
            1 => Ok(found.remove(0)),
            _ => Err(HsmError::KeyReferenceAmbiguous),
        }
    }

    /// Generate a persistent, non-extractable ML-DSA-65 key pair in the token.
    pub fn generate_mldsa65_ca_key(&self, label: &str) -> Result<Pkcs11KeyRef, HsmError> {
        validate_label(label)?;
        let session = self.open_session()?;
        let existing = session
            .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        if !existing.is_empty() {
            return Err(HsmError::KeyAlreadyExists);
        }
        let mut id = [0u8; 20];
        fill(&mut id).map_err(|_| HsmError::Randomness)?;
        let public_template = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_65.into()),
        ];
        let private_template = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_65.into()),
        ];
        let (public_handle, private_handle) = session
            .generate_key_pair(
                &Mechanism::MlDsaKeyPairGen,
                &public_template,
                &private_template,
            )
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let public_key = match session.get_attributes(public_handle, &[AttributeType::Value]) {
            Ok(attributes) => attributes
                .into_iter()
                .find_map(|attribute| match attribute {
                    Attribute::Value(value) => Some(value),
                    _ => None,
                })
                .ok_or(HsmError::InvalidPublicKey),
            Err(error) => Err(HsmError::Pkcs11(error.to_string())),
        };
        let public_key = match public_key {
            Ok(value) => value,
            Err(error) => {
                let _ = session.destroy_object(public_handle);
                let _ = session.destroy_object(private_handle);
                return Err(error);
            }
        };
        if parse_public_key(&public_key).is_err() {
            let _ = session.destroy_object(public_handle);
            let _ = session.destroy_object(private_handle);
            return Err(HsmError::InvalidPublicKey);
        }
        Ok(Pkcs11KeyRef {
            id: id.to_vec(),
            label: label.to_owned(),
            token_label: self.token_label.clone(),
            token_serial: self.token_serial.clone(),
            public_key,
        })
    }

    /// Sign bytes with the token-resident key. Private key material is never read or returned.
    pub fn sign_mldsa65(&self, key: &Pkcs11KeyRef, message: &[u8]) -> Result<Vec<u8>, HsmError> {
        if key.token_label != self.token_label || key.token_serial != self.token_serial {
            return Err(HsmError::InvalidConfig);
        }
        if message.len() > 1024 * 1024 {
            return Err(HsmError::MessageTooLarge);
        }
        let session = self.open_session()?;
        let private_handle = self.find_key(&session, &key.id, ObjectClass::PRIVATE_KEY)?;
        let mechanism = Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Required, None));
        session
            .sign(&mechanism, private_handle, message)
            .map_err(|e| HsmError::Pkcs11(e.to_string()))
    }

    /// Read only the public object and compare it with a persisted key reference.
    pub fn read_public_key_bytes(&self, key: &Pkcs11KeyRef) -> Result<Vec<u8>, HsmError> {
        if key.token_label != self.token_label || key.token_serial != self.token_serial {
            return Err(HsmError::InvalidConfig);
        }
        let session = self.open_session()?;
        let public_handle = self.find_key(&session, &key.id, ObjectClass::PUBLIC_KEY)?;
        let attributes = session
            .get_attributes(public_handle, &[AttributeType::Value])
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::Value(value) => Some(value),
                _ => None,
            })
            .ok_or(HsmError::InvalidPublicKey)
    }

    /// Delete both public and private token objects for this reference. This is destructive.
    pub fn destroy_key(&self, key: &Pkcs11KeyRef) -> Result<(), HsmError> {
        if key.token_label != self.token_label || key.token_serial != self.token_serial {
            return Err(HsmError::InvalidConfig);
        }
        let session = self.open_session()?;
        let private = self.find_key(&session, &key.id, ObjectClass::PRIVATE_KEY);
        let public = self.find_key(&session, &key.id, ObjectClass::PUBLIC_KEY);
        let private = match private {
            Ok(handle) => Some(handle),
            Err(HsmError::KeyNotFound) => None,
            Err(error) => return Err(error),
        };
        let public = match public {
            Ok(handle) => Some(handle),
            Err(HsmError::KeyNotFound) => None,
            Err(error) => return Err(error),
        };
        if private.is_none() && public.is_none() {
            return Err(HsmError::KeyNotFound);
        }
        if let Some(handle) = private {
            session
                .destroy_object(handle)
                .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        }
        if let Some(handle) = public {
            session
                .destroy_object(handle)
                .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        }
        Ok(())
    }

    /// Verify token object policy without requesting private key material.
    pub fn private_key_is_non_extractable(&self, key: &Pkcs11KeyRef) -> Result<bool, HsmError> {
        if key.token_label != self.token_label || key.token_serial != self.token_serial {
            return Err(HsmError::InvalidConfig);
        }
        let session = self.open_session()?;
        let private_handle = self.find_key(&session, &key.id, ObjectClass::PRIVATE_KEY)?;
        let attributes = session
            .get_attributes(
                private_handle,
                &[AttributeType::Extractable, AttributeType::Sensitive],
            )
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let mut extractable = None;
        let mut sensitive = None;
        for attribute in attributes {
            match attribute {
                Attribute::Extractable(value) => extractable = Some(value),
                Attribute::Sensitive(value) => sensitive = Some(value),
                _ => {}
            }
        }
        Ok(extractable == Some(false) && sensitive == Some(true))
    }
}

/// Opaque reference to a token-resident, non-extractable AES-256 key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pkcs11AesKeyRef {
    id: Vec<u8>,
    label: String,
    token_label: String,
    token_serial: String,
}
impl Pkcs11AesKeyRef {
    /// PKCS#11 token label bound to this key reference.
    pub fn token_label(&self) -> &str {
        &self.token_label
    }
    /// PKCS#11 token serial bound to this key reference.
    pub fn token_serial(&self) -> &str {
        &self.token_serial
    }
}

impl fmt::Debug for Pkcs11AesKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11AesKeyRef")
            .field("id", &"[redacted]")
            .field("label", &self.label)
            .field("token_label", &self.token_label)
            .field("token_serial", &self.token_serial)
            .finish()
    }
}

/// AES-GCM output from the HSM. The key itself never leaves the token.
#[derive(Debug, Clone)]
pub struct AesGcmCiphertext {
    pub ciphertext: Vec<u8>,
    pub initialization_vector: Vec<u8>,
    pub authentication_tag: Vec<u8>,
}

impl Pkcs11Provider {
    /// Generate a persistent, sensitive, non-extractable AES-256 key for XKS.
    pub fn generate_aes256_gcm_key(&self, label: &str) -> Result<Pkcs11AesKeyRef, HsmError> {
        validate_label(label)?;
        let session = self.open_session()?;
        let existing = session
            .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        if !existing.is_empty() {
            return Err(HsmError::KeyAlreadyExists);
        }
        let mut id = [0u8; 20];
        fill(&mut id).map_err(|_| HsmError::Randomness)?;
        session
            .generate_key(
                &Mechanism::AesKeyGen,
                &[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                    Attribute::ValueLen(32.into()),
                    Attribute::Label(label.as_bytes().to_vec()),
                    Attribute::Id(id.to_vec()),
                ],
            )
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let key = Pkcs11AesKeyRef {
            id: id.to_vec(),
            label: label.to_owned(),
            token_label: self.token_label.clone(),
            token_serial: self.token_serial.clone(),
        };
        match self.aes256_key_is_protected(&key) {
            Ok(true) => Ok(key),
            Ok(false) => {
                let _ = self.destroy_aes256_gcm_key(&key);
                Err(HsmError::InvalidConfig)
            }
            Err(error) => {
                let _ = self.destroy_aes256_gcm_key(&key);
                Err(error)
            }
        }
    }

    fn find_aes_key(
        &self,
        session: &Session,
        key: &Pkcs11AesKeyRef,
    ) -> Result<ObjectHandle, HsmError> {
        if key.token_label != self.token_label || key.token_serial != self.token_serial {
            return Err(HsmError::InvalidConfig);
        }
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Id(key.id.clone()),
        ];
        let mut found = session
            .find_objects(&template)
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        match found.len() {
            0 => Err(HsmError::KeyNotFound),
            1 => Ok(found.remove(0)),
            _ => Err(HsmError::KeyReferenceAmbiguous),
        }
    }

    /// Confirm that the referenced key is AES-256, sensitive and non-extractable.
    pub fn aes256_key_is_protected(&self, key: &Pkcs11AesKeyRef) -> Result<bool, HsmError> {
        let session = self.open_session()?;
        let handle = self.find_aes_key(&session, key)?;
        let attrs = session
            .get_attributes(
                handle,
                &[
                    AttributeType::ValueLen,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                ],
            )
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let mut len_32 = None;
        let mut sensitive = None;
        let mut extractable = None;
        let mut encrypt = None;
        let mut decrypt = None;
        for attr in attrs {
            match attr {
                Attribute::ValueLen(v) => len_32 = Some(*v == 32_u64),
                Attribute::Sensitive(v) => sensitive = Some(v),
                Attribute::Extractable(v) => extractable = Some(v),
                Attribute::Encrypt(v) => encrypt = Some(v),
                Attribute::Decrypt(v) => decrypt = Some(v),
                _ => {}
            }
        }
        Ok(len_32 == Some(true)
            && sensitive == Some(true)
            && extractable == Some(false)
            && encrypt == Some(true)
            && decrypt == Some(true))
    }

    /// Perform AES-256-GCM inside the token and return ciphertext, IV and detached tag.
    pub fn encrypt_aes256_gcm(
        &self,
        key: &Pkcs11AesKeyRef,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<AesGcmCiphertext, HsmError> {
        let session = self.open_session()?;
        let handle = self.find_aes_key(&session, key)?;
        let mut iv = [0u8; 12];
        fill(&mut iv).map_err(|_| HsmError::Randomness)?;
        let mut encrypted = {
            let mechanism = Mechanism::AesGcm(
                GcmParams::new(&mut iv, aad, 128.into())
                    .map_err(|e| HsmError::Pkcs11(e.to_string()))?,
            );
            session
                .encrypt(&mechanism, handle, plaintext)
                .map_err(|e| HsmError::Pkcs11(e.to_string()))?
        };
        if encrypted.len() < 16 {
            return Err(HsmError::Pkcs11(
                "HSM returned a truncated AES-GCM result".into(),
            ));
        }
        let tag = encrypted.split_off(encrypted.len() - 16);
        Ok(AesGcmCiphertext {
            ciphertext: encrypted,
            initialization_vector: iv.to_vec(),
            authentication_tag: tag,
        })
    }

    /// Decrypt AES-256-GCM inside the token. Authentication failures return an error without plaintext.
    pub fn decrypt_aes256_gcm(
        &self,
        key: &Pkcs11AesKeyRef,
        ciphertext: &[u8],
        iv: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        if !(iv.len() == 12 || iv.len() == 16) || tag.len() != 16 {
            return Err(HsmError::InvalidConfig);
        }
        let session = self.open_session()?;
        let handle = self.find_aes_key(&session, key)?;
        let mut nonce = iv.to_vec();
        let mechanism = Mechanism::AesGcm(
            GcmParams::new(&mut nonce, aad, 128.into())
                .map_err(|e| HsmError::Pkcs11(e.to_string()))?,
        );
        let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(tag);
        session
            .decrypt(&mechanism, handle, &combined)
            .map_err(|error| match error {
                CryptokiError::Pkcs11(
                    RvError::EncryptedDataInvalid | RvError::EncryptedDataLenRange,
                    _,
                ) => HsmError::InvalidCiphertext,
                other => HsmError::Pkcs11(other.to_string()),
            })
    }

    /// Destroy a token-resident AES key after an independently authorized lifecycle operation.
    pub fn destroy_aes256_gcm_key(&self, key: &Pkcs11AesKeyRef) -> Result<(), HsmError> {
        let session = self.open_session()?;
        let handle = self.find_aes_key(&session, key)?;
        session
            .destroy_object(handle)
            .map_err(|e| HsmError::Pkcs11(e.to_string()))
    }

    /// Exercise AES-256-GCM with a dedicated, non-exportable health-check key inside the token.
    pub fn aes256_gcm_self_test(&self, key: &Pkcs11AesKeyRef) -> Result<(), HsmError> {
        if !self.aes256_key_is_protected(key)? {
            return Err(HsmError::InvalidConfig);
        }
        let plaintext = b"NEXUS-Q XKS HSM health probe";
        let aad = b"NEXUS-Q XKS health check";
        let encrypted = self.encrypt_aes256_gcm(key, plaintext, aad)?;
        let recovered = self.decrypt_aes256_gcm(
            key,
            &encrypted.ciphertext,
            &encrypted.initialization_vector,
            &encrypted.authentication_tag,
            aad,
        )?;
        if recovered.as_slice() != plaintext {
            return Err(HsmError::Pkcs11(
                "AES-GCM self-test round-trip mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Check that the PKCS#11 token can accept an authenticated session.
    pub fn health_check(&self) -> Result<(), HsmError> {
        self.open_session().map(|_| ())
    }
}

fn parse_public_key(bytes: &[u8]) -> Result<VerifyingKey<MlDsa65>, HsmError> {
    let encoded =
        EncodedVerifyingKey::<MlDsa65>::try_from(bytes).map_err(|_| HsmError::InvalidPublicKey)?;
    Ok(VerifyingKey::<MlDsa65>::decode(&encoded))
}

fn validate_label(label: &str) -> Result<(), HsmError> {
    if label.is_empty()
        || label.len() > 64
        || !label.is_ascii()
        || label.chars().any(char::is_control)
    {
        return Err(HsmError::InvalidLabel);
    }
    Ok(())
}

/// Trait used by the M-of-N ceremony coordinator. Implementations must keep private keys inside an HSM.
pub trait HsmKeyStore: Send + Sync {
    /// Generate a non-extractable ML-DSA-65 CA key after the ceremony quorum has been reached.
    fn generate_mldsa65_ca_key(&self, label: &str) -> Result<Pkcs11KeyRef, HsmError>;
    /// Destroy the referenced key pair after a separately authorized ceremony.
    fn destroy_key(&self, key: &Pkcs11KeyRef) -> Result<(), HsmError>;
}
impl HsmKeyStore for Pkcs11Provider {
    fn generate_mldsa65_ca_key(&self, label: &str) -> Result<Pkcs11KeyRef, HsmError> {
        Pkcs11Provider::generate_mldsa65_ca_key(self, label)
    }
    fn destroy_key(&self, key: &Pkcs11KeyRef) -> Result<(), HsmError> {
        Pkcs11Provider::destroy_key(self, key)
    }
}

/// HSM-backed ML-DSA-65 signer accepted directly by `EnrollmentAuthority::new_with_signer`.
pub struct Pkcs11MlDsaSigner {
    provider: Arc<Pkcs11Provider>,
    key: Pkcs11KeyRef,
    verifying_key: VerifyingKey<MlDsa65>,
}
impl fmt::Debug for Pkcs11MlDsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11MlDsaSigner")
            .field("key", &self.key)
            .finish()
    }
}
impl Pkcs11MlDsaSigner {
    /// Bind a token key reference to the enrollment/X.509 signer interface.
    pub fn new(provider: Arc<Pkcs11Provider>, key: Pkcs11KeyRef) -> Result<Self, HsmError> {
        if key.token_label != provider.token_label {
            return Err(HsmError::InvalidConfig);
        }
        let token_public_key = provider.read_public_key_bytes(&key)?;
        if token_public_key != key.public_key {
            return Err(HsmError::InvalidPublicKey);
        }
        let verifying_key = parse_public_key(&token_public_key)?;
        Ok(Self {
            provider,
            key,
            verifying_key,
        })
    }
    /// Return the public token reference.
    pub fn key_ref(&self) -> &Pkcs11KeyRef {
        &self.key
    }
    /// Return the public verification key; no private key material is exposed.
    pub fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        self.verifying_key.clone()
    }
}
impl nexusq_x509::MlDsa65Signer for Pkcs11MlDsaSigner {
    fn public_key(&self) -> VerifyingKey<MlDsa65> {
        self.verifying_key.clone()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.provider
            .sign_mldsa65(&self.key, message)
            .map_err(|_| "PKCS#11 ML-DSA signing operation failed".to_owned())
    }
}

impl Pkcs11KeyRef {
    #[cfg(test)]
    pub(crate) fn from_parts(
        id: Vec<u8>,
        label: String,
        token_label: String,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            id,
            label,
            token_label,
            token_serial: "test-serial".to_owned(),
            public_key,
        }
    }
}

use std::{fmt, sync::Arc};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        Mechanism,
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
        });
        let _session = provider.open_session()?;
        Ok(provider)
    }

    fn open_session(&self) -> Result<Session, HsmError> {
        let session = self
            .context
            .open_rw_session(self.slot)
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
        let pin = AuthPin::new(self.pin.as_str().to_owned().into());
        session
            .login(UserType::User, Some(&pin))
            .map_err(|e| HsmError::Pkcs11(e.to_string()))?;
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

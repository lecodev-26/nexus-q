//! PKCS#11 adapter for AES-256-GCM keys that remain inside an HSM token.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use nexusq_hsm::{HsmError, Pkcs11AesKeyRef, Pkcs11Provider};

use crate::{
    EkmFleetDetail, ErrorCode, GetHealthStatusResponse, GetKeyMetadataResponse, KeyStatus,
    ProviderCiphertext, RequestMetadata, XksError, encode_xks_aad, service::XksKeyProvider,
};

/// Routes configured external key IDs to pre-provisioned non-extractable PKCS#11 AES-256 keys.
pub struct Pkcs11XksProvider {
    provider: Arc<Pkcs11Provider>,
    keys: HashMap<String, Pkcs11AesKeyRef>,
    health_check_key: Pkcs11AesKeyRef,
    ekm_vendor: String,
    ekm_model: String,
    health_cache: Mutex<Option<(Instant, GetHealthStatusResponse)>>,
}

impl Pkcs11XksProvider {
    /// Build an explicit allow-list. Keys are never generated implicitly by an XKS request.
    pub fn new(
        provider: Arc<Pkcs11Provider>,
        keys: impl IntoIterator<Item = (String, Pkcs11AesKeyRef)>,
        health_check_key: Pkcs11AesKeyRef,
        ekm_vendor: impl Into<String>,
        ekm_model: impl Into<String>,
    ) -> Result<Self, XksError> {
        let mut mapped = HashMap::new();
        for (external_id, key) in keys {
            if !provider
                .aes256_key_is_protected(&key)
                .map_err(map_hsm_error)?
            {
                return Err(XksError::new(
                    ErrorCode::InvalidState,
                    "Mapped PKCS#11 key must be a protected AES-256 key",
                ));
            }
            if external_id.is_empty()
                || external_id.len() > 128
                || !external_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
                || mapped.insert(external_id, key).is_some()
            {
                return Err(XksError::new(
                    ErrorCode::InvalidRequest,
                    "Invalid or duplicate external key mapping",
                ));
            }
        }
        if mapped.is_empty() {
            return Err(XksError::new(
                ErrorCode::InvalidRequest,
                "At least one external key mapping is required",
            ));
        }
        if !provider
            .aes256_key_is_protected(&health_check_key)
            .map_err(map_hsm_error)?
        {
            return Err(XksError::new(
                ErrorCode::InvalidState,
                "Health-check key must be a protected AES-256 key",
            ));
        }
        let adapter = Self {
            provider,
            keys: mapped,
            health_check_key,
            ekm_vendor: ekm_vendor.into(),
            ekm_model: ekm_model.into(),
            health_cache: Mutex::new(None),
        };
        adapter.refresh_health()?;
        Ok(adapter)
    }

    /// Run a deep HSM check and refresh the result returned to AWS KMS for up to one minute.
    pub fn refresh_health(&self) -> Result<(), XksError> {
        self.provider.health_check().map_err(map_hsm_error)?;
        let key = self.keys.values().next().ok_or_else(|| {
            XksError::new(
                ErrorCode::InvalidState,
                "No external AES keys are configured",
            )
        })?;
        if !self
            .provider
            .aes256_key_is_protected(key)
            .map_err(map_hsm_error)?
        {
            return Err(XksError::new(
                ErrorCode::InvalidState,
                "Configured external key is not a protected AES-256 key",
            ));
        }
        self.provider
            .aes256_gcm_self_test(&self.health_check_key)
            .map_err(map_hsm_error)?;
        let response = self.health_response("ACTIVE");
        *self
            .health_cache
            .lock()
            .map_err(|_| XksError::new(ErrorCode::Internal, "Health cache is unavailable"))? =
            Some((Instant::now(), response));
        Ok(())
    }

    fn health_response(&self, status: &str) -> GetHealthStatusResponse {
        let token = self.keys.values().next();
        GetHealthStatusResponse {
            xks_proxy_fleet_size: 1,
            xks_proxy_vendor: "NEXUS-Q".into(),
            xks_proxy_model: env!("CARGO_PKG_VERSION").into(),
            ekm_vendor: self.ekm_vendor.clone(),
            ekm_fleet_details: vec![EkmFleetDetail {
                id: token
                    .map(|key| key.token_serial().to_owned())
                    .unwrap_or_else(|| "pkcs11-token".into()),
                model: self.ekm_model.clone(),
                health_status: status.into(),
            }],
        }
    }

    fn key(&self, external_id: &str) -> Result<&Pkcs11AesKeyRef, XksError> {
        self.keys
            .get(external_id)
            .ok_or_else(|| XksError::new(ErrorCode::InvalidKey, "External key was not found"))
    }
}

impl XksKeyProvider for Pkcs11XksProvider {
    fn health_check(&self) -> Result<GetHealthStatusResponse, XksError> {
        if let Ok(cache) = self.health_cache.lock() {
            if let Some((created_at, response)) = cache.as_ref() {
                if created_at.elapsed() < Duration::from_secs(60) {
                    return Ok(response.clone());
                }
            }
        }
        match self.refresh_health() {
            Ok(()) => self
                .health_cache
                .lock()
                .map_err(|_| XksError::new(ErrorCode::Internal, "Health cache is unavailable"))?
                .as_ref()
                .map(|(_, response)| response.clone())
                .ok_or_else(|| XksError::new(ErrorCode::Internal, "Health cache is empty")),
            Err(_) => Ok(self.health_response("UNAVAILABLE")),
        }
    }

    fn key_metadata(
        &self,
        external_key_id: &str,
        _metadata: &RequestMetadata,
    ) -> Result<GetKeyMetadataResponse, XksError> {
        let key = self.key(external_key_id)?;
        if !self
            .provider
            .aes256_key_is_protected(key)
            .map_err(map_hsm_error)?
        {
            return Err(XksError::new(
                ErrorCode::InvalidState,
                "External AES key is not a protected AES-256 key",
            ));
        }
        Ok(GetKeyMetadataResponse {
            key_spec: "AES_256",
            key_usage: vec!["ENCRYPT", "DECRYPT"],
            key_status: KeyStatus::Enabled,
        })
    }

    fn encrypt(
        &self,
        external_key_id: &str,
        plaintext: &[u8],
        aad: &[u8],
        _metadata: &RequestMetadata,
    ) -> Result<ProviderCiphertext, XksError> {
        let key = self.key(external_key_id)?;
        let framed_aad = encode_xks_aad(aad, &[])?;
        let encrypted = self
            .provider
            .encrypt_aes256_gcm(key, plaintext, &framed_aad)
            .map_err(map_hsm_error)?;
        Ok(ProviderCiphertext {
            ciphertext: encrypted.ciphertext,
            initialization_vector: encrypted.initialization_vector,
            authentication_tag: encrypted.authentication_tag,
            ciphertext_metadata: Vec::new(),
        })
    }

    fn decrypt(
        &self,
        external_key_id: &str,
        ciphertext: &[u8],
        iv: &[u8],
        tag: &[u8],
        metadata: &[u8],
        aad: &[u8],
        _request_metadata: &RequestMetadata,
    ) -> Result<Vec<u8>, XksError> {
        if !metadata.is_empty() {
            return Err(XksError::new(
                ErrorCode::InvalidCiphertext,
                "This PKCS#11 adapter does not use ciphertext metadata",
            ));
        }
        let key = self.key(external_key_id)?;
        let framed_aad = encode_xks_aad(aad, metadata)?;
        self.provider
            .decrypt_aes256_gcm(key, ciphertext, iv, tag, &framed_aad)
            .map_err(|error| match error {
                HsmError::KeyNotFound => {
                    XksError::new(ErrorCode::InvalidKey, "External key was not found")
                }
                HsmError::InvalidCiphertext => XksError::new(
                    ErrorCode::InvalidCiphertext,
                    "Ciphertext authentication failed",
                ),
                other => map_hsm_error(other),
            })
    }
}

fn map_hsm_error(error: HsmError) -> XksError {
    match error {
        HsmError::KeyNotFound => XksError::new(ErrorCode::InvalidKey, "External key was not found"),
        HsmError::InvalidConfig
        | HsmError::InvalidLabel
        | HsmError::KeyAlreadyExists
        | HsmError::KeyReferenceAmbiguous => XksError::new(
            ErrorCode::InvalidState,
            "External key manager configuration is invalid",
        ),
        HsmError::InvalidCiphertext => XksError::new(
            ErrorCode::InvalidCiphertext,
            "Ciphertext authentication failed",
        ),
        HsmError::Pkcs11(_)
        | HsmError::InvalidPublicKey
        | HsmError::MessageTooLarge
        | HsmError::Randomness => {
            XksError::new(ErrorCode::Internal, "External key manager operation failed")
        }
    }
}

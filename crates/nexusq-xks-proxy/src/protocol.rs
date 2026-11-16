use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestMetadata {
    #[serde(default)]
    pub aws_principal_arn: Option<String>,
    #[serde(default)]
    pub aws_source_vpc: Option<String>,
    #[serde(default)]
    pub aws_source_vpce: Option<String>,
    #[serde(default)]
    pub kms_key_arn: Option<String>,
    #[serde(default)]
    pub kms_operation: Option<String>,
    #[serde(default)]
    pub kms_request_id: Option<String>,
    #[serde(default)]
    pub kms_via_service: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyMetadataRequest {
    pub request_metadata: RequestMetadata,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyMetadataResponse {
    pub key_spec: &'static str,
    pub key_usage: Vec<&'static str>,
    pub key_status: KeyStatus,
}
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyStatus {
    Enabled,
    Disabled,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptRequest {
    pub request_metadata: RequestMetadata,
    pub plaintext: String,
    pub encryption_algorithm: String,
    #[serde(default)]
    pub additional_authenticated_data: Option<String>,
    #[serde(default)]
    pub ciphertext_data_integrity_value_algorithm: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptResponse {
    pub ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext_metadata: Option<String>,
    pub initialization_vector: String,
    pub authentication_tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext_data_integrity_value: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptRequest {
    pub request_metadata: RequestMetadata,
    pub ciphertext: String,
    #[serde(default)]
    pub ciphertext_metadata: Option<String>,
    pub initialization_vector: String,
    pub authentication_tag: String,
    pub encryption_algorithm: String,
    #[serde(default)]
    pub additional_authenticated_data: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptResponse {
    pub plaintext: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetHealthStatusRequest {
    #[serde(default)]
    pub request_metadata: RequestMetadata,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetHealthStatusResponse {
    pub xks_proxy_fleet_size: u32,
    pub xks_proxy_vendor: String,
    pub xks_proxy_model: String,
    pub ekm_vendor: String,
    pub ekm_fleet_details: Vec<EkmFleetDetail>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EkmFleetDetail {
    pub id: String,
    pub model: String,
    pub health_status: String,
}

#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    AuthenticationFailed,
    AccessDenied,
    InvalidCiphertext,
    InvalidKeyUsage,
    InvalidState,
    InvalidKey,
    InvalidUriPath,
    InvalidRequest,
    Throttling,
    DependencyTimeout,
    DependencyUnavailable,
    UnsupportedOperation,
    Internal,
}
impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "AuthenticationFailedException",
            Self::AccessDenied => "AccessDeniedException",
            Self::InvalidCiphertext => "InvalidCiphertextException",
            Self::InvalidKeyUsage => "InvalidKeyUsageException",
            Self::InvalidState => "InvalidStateException",
            Self::InvalidKey => "KeyNotFoundException",
            Self::InvalidUriPath => "InvalidUriPathException",
            Self::InvalidRequest => "ValidationException",
            Self::Throttling => "ThrottlingException",
            Self::DependencyTimeout => "DependencyTimeoutException",
            Self::DependencyUnavailable => "InternalException",
            Self::UnsupportedOperation => "UnsupportedOperationException",
            Self::Internal => "InternalException",
        }
    }
}
#[derive(Debug, Error)]
#[error("{message}")]
pub struct XksError {
    pub code: ErrorCode,
    pub message: String,
}
impl XksError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Construct the authenticated data required by the AWS XKS v1 wire protocol.
/// Both lengths are encoded before concatenating the raw binary fields.
pub fn encode_xks_aad(aad: &[u8], ciphertext_metadata: &[u8]) -> Result<Vec<u8>, XksError> {
    let aad_len = u16::try_from(aad.len()).map_err(|_| {
        XksError::new(
            ErrorCode::InvalidRequest,
            "XKS AAD exceeds the supported length",
        )
    })?;
    let metadata_len = u8::try_from(ciphertext_metadata.len()).map_err(|_| {
        XksError::new(
            ErrorCode::InvalidRequest,
            "XKS ciphertext metadata exceeds the supported length",
        )
    })?;
    if aad_len > 8192 || metadata_len > 20 {
        return Err(XksError::new(
            ErrorCode::InvalidRequest,
            "XKS AAD or ciphertext metadata exceeds the supported length",
        ));
    }
    let mut encoded = Vec::with_capacity(2 + aad.len() + 1 + ciphertext_metadata.len());
    encoded.extend_from_slice(&aad_len.to_be_bytes());
    encoded.extend_from_slice(aad);
    encoded.push(metadata_len);
    encoded.extend_from_slice(ciphertext_metadata);
    Ok(encoded)
}

#[cfg(test)]
mod aad_tests {
    use super::encode_xks_aad;

    #[test]
    fn encodes_aad_and_metadata_lengths_before_the_fields() {
        assert_eq!(encode_xks_aad(b"abc", b"xy").unwrap(), b"\0\x03abc\x02xy");
        assert_eq!(encode_xks_aad(b"", b"").unwrap(), b"\0\0\0");
    }
}

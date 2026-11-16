use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{OriginalUri, Path, State},
    http::{Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    auth::{self, AuthConfig, AuthCredential},
    protocol::*,
};

const MAX_BODY: usize = 32 * 1024;
const MAX_PLAINTEXT: usize = 4300;
const MAX_AAD: usize = 8192;

/// Cryptographic boundary for an external key manager.
/// Implementations MUST operate on non-exportable key handles and MUST NOT
/// return key material to this process. Implementations MUST authenticate the
/// XKS-framed AAD (`u16_be(aad_len) || aad || u8(metadata_len) || metadata`)
/// using `encode_xks_aad`, rather than passing raw AAD directly to AES-GCM.
/// Calls are synchronous and dispatched
/// on Tokio's blocking pool by the HTTP handlers.
pub trait XksKeyProvider: Send + Sync + 'static {
    fn health_check(&self) -> Result<GetHealthStatusResponse, XksError>;
    fn key_metadata(
        &self,
        external_key_id: &str,
        metadata: &RequestMetadata,
    ) -> Result<GetKeyMetadataResponse, XksError>;
    fn encrypt(
        &self,
        external_key_id: &str,
        plaintext: &[u8],
        aad: &[u8],
        metadata: &RequestMetadata,
    ) -> Result<ProviderCiphertext, XksError>;
    fn decrypt(
        &self,
        external_key_id: &str,
        request: ProviderDecryptRequest<'_>,
    ) -> Result<Vec<u8>, XksError>;
}

/// Binary AES-GCM result returned by the protected key manager.
#[derive(Debug, Clone)]
pub struct ProviderCiphertext {
    pub ciphertext: Vec<u8>,
    pub initialization_vector: Vec<u8>,
    pub authentication_tag: Vec<u8>,
    pub ciphertext_metadata: Vec<u8>,
}

/// Authenticated decryption input passed to an external key manager.
#[derive(Debug, Clone, Copy)]
pub struct ProviderDecryptRequest<'a> {
    pub ciphertext: &'a [u8],
    pub initialization_vector: &'a [u8],
    pub authentication_tag: &'a [u8],
    pub ciphertext_metadata: &'a [u8],
    pub additional_authenticated_data: &'a [u8],
    pub request_metadata: &'a RequestMetadata,
}

#[derive(Clone)]
pub struct SigV4Credential {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
}

#[derive(Clone)]
pub struct XksProxyConfig {
    /// Prefix ending in `/kms/xks/v1`, e.g. `/tenant-a/kms/xks/v1`.
    pub uri_path: String,
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    /// Optional previous/next credential accepted simultaneously during rotation.
    pub additional_credentials: Vec<SigV4Credential>,
}
impl XksProxyConfig {
    pub fn validate(&self) -> Result<(), XksError> {
        if self.additional_credentials.len() > 1 {
            return Err(XksError::new(
                ErrorCode::InvalidRequest,
                "At most two SigV4 credentials may be active",
            ));
        }
        let mut seen_ids: Vec<&str> = Vec::with_capacity(2);
        let credentials = std::iter::once((&self.access_key_id, self.secret_access_key.as_str()))
            .chain(self.additional_credentials.iter().map(|credential| {
                (
                    &credential.access_key_id,
                    credential.secret_access_key.as_str(),
                )
            }));
        for (access_key_id, secret_access_key) in credentials {
            let valid_id = (20..=30).contains(&access_key_id.len())
                && access_key_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/-_".contains(&b));
            let valid_secret = (43..=64).contains(&secret_access_key.len())
                && secret_access_key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b));
            if !valid_id || !valid_secret || seen_ids.contains(&access_key_id.as_str()) {
                return Err(XksError::new(
                    ErrorCode::InvalidRequest,
                    "XKS SigV4 credentials are invalid or duplicated",
                ));
            }
            seen_ids.push(access_key_id.as_str());
        }
        if self.uri_path.len() > 128
            || !self.uri_path.starts_with('/')
            || !self.uri_path.ends_with("/kms/xks/v1")
            || !self
                .uri_path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_".contains(&b))
        {
            return Err(XksError::new(
                ErrorCode::InvalidRequest,
                "XKS URI path must be a valid path ending in /kms/xks/v1 and at most 128 characters",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    provider: Arc<dyn XksKeyProvider>,
    auth: AuthConfig,
    concurrency: Arc<Semaphore>,
    provider_slots: Arc<Semaphore>,
}

/// Build the XKS v1 router. TLS termination is intentionally deployment-owned;
/// production deployments must expose this router only behind TLS 1.2+.
pub fn router(
    config: XksProxyConfig,
    provider: Arc<dyn XksKeyProvider>,
) -> Result<Router, XksError> {
    config.validate()?;
    let base = config.uri_path.clone();
    let mut credentials = vec![AuthCredential {
        access_key_id: config.access_key_id.clone(),
        secret_access_key: config.secret_access_key.clone(),
    }];
    credentials.extend(
        config
            .additional_credentials
            .iter()
            .map(|credential| AuthCredential {
                access_key_id: credential.access_key_id.clone(),
                secret_access_key: credential.secret_access_key.clone(),
            }),
    );
    let state = AppState {
        provider,
        auth: AuthConfig { credentials },
        concurrency: Arc::new(Semaphore::new(256)),
        provider_slots: Arc::new(Semaphore::new(128)),
    };
    let load_balancer_health = Router::new().route("/healthz", get(load_balancer_health));
    let xks_api = Router::new()
        .route("/health", post(health))
        .route("/keys/{external_key_id}/metadata", post(metadata))
        .route("/keys/{external_key_id}/encrypt", post(encrypt))
        .route("/keys/{external_key_id}/decrypt", post(decrypt))
        .fallback(|| async {
            error_response(XksError::new(
                ErrorCode::InvalidUriPath,
                "XKS URI path is invalid",
            ))
        })
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    let api = load_balancer_health.merge(xks_api).with_state(state);
    Ok(Router::new()
        .nest(&base, api)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY)))
}

async fn authenticate(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let permit: OwnedSemaphorePermit = match state.concurrency.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return error_response(XksError::new(
                ErrorCode::Throttling,
                "XKS proxy is at capacity",
            ));
        }
    };
    let bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return error_response(XksError::new(
                ErrorCode::InvalidRequest,
                "Request body exceeds the XKS limit",
            ));
        }
    };
    if parts.method != Method::POST {
        return (StatusCode::METHOD_NOT_ALLOWED, "").into_response();
    }
    if parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next() == Some("application/json"))
        != Some(true)
    {
        return error_response(XksError::new(
            ErrorCode::InvalidRequest,
            "Content-Type must be application/json",
        ));
    }
    let signed_uri = parts
        .extensions
        .get::<OriginalUri>()
        .map(|original| &original.0)
        .unwrap_or(&parts.uri);
    if let Err(error) = auth::verify(
        &state.auth,
        &parts.method,
        signed_uri,
        &parts.headers,
        &bytes,
    ) {
        return error_response(error);
    }
    parts.extensions.insert(Arc::new(permit));
    let request = Request::from_parts(parts, Body::from(bytes));
    next.run(request).await
}

async fn load_balancer_health(State(state): State<AppState>) -> Response {
    let provider = state.provider.clone();
    match run_provider(&state, move || provider.health_check()).await {
        Ok(status)
            if status
                .ekm_fleet_details
                .iter()
                .all(|detail| detail.health_status != "UNAVAILABLE") =>
        {
            StatusCode::OK.into_response()
        }
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn health(State(state): State<AppState>, body: Bytes) -> Response {
    let request: GetHealthStatusRequest = match parse_request(&body) {
        Ok(value) => value,
        Err(_) => {
            return error_response(XksError::new(
                ErrorCode::Internal,
                "Invalid GetHealthStatus request",
            ));
        }
    };
    if request.request_metadata.kms_request_id.is_none()
        || request.request_metadata.kms_operation.is_none()
    {
        return error_response(XksError::new(
            ErrorCode::Internal,
            "GetHealthStatus request metadata is incomplete",
        ));
    }
    tracing::info!(
        kms_request_id = request
            .request_metadata
            .kms_request_id
            .as_deref()
            .unwrap_or("unknown"),
        kms_operation = request
            .request_metadata
            .kms_operation
            .as_deref()
            .unwrap_or("unknown"),
        "XKS GetHealthStatus request"
    );
    let provider = state.provider.clone();
    match run_provider(&state, move || provider.health_check()).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error_response(error),
    }
}
async fn metadata(State(state): State<AppState>, Path(key): Path<String>, body: Bytes) -> Response {
    let request: GetKeyMetadataRequest = match parse_request(&body) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    if !valid_key_id(&key) {
        return error_response(XksError::new(
            ErrorCode::InvalidUriPath,
            "External key identifier is not valid in an XKS URI",
        ));
    }
    let provider = state.provider.clone();
    let metadata = request.request_metadata;
    tracing::info!(
        external_key_id = %key,
        kms_request_id = metadata.kms_request_id.as_deref().unwrap_or("unknown"),
        kms_operation = metadata.kms_operation.as_deref().unwrap_or("unknown"),
        "XKS GetKeyMetadata request"
    );
    match run_provider(&state, move || provider.key_metadata(&key, &metadata)).await {
        Ok(response)
            if response.key_spec == "AES_256"
                && response.key_usage.len() <= 10
                && response.key_usage.contains(&"ENCRYPT")
                && response.key_usage.contains(&"DECRYPT") =>
        {
            Json(response).into_response()
        }
        Ok(_) => error_response(XksError::new(
            ErrorCode::Internal,
            "Key manager metadata is not XKS v1 compatible",
        )),
        Err(error) => error_response(error),
    }
}
async fn encrypt(State(state): State<AppState>, Path(key): Path<String>, body: Bytes) -> Response {
    let mut request: EncryptRequest = match parse_request(&body) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    if !valid_key_id(&key) {
        return error_response(XksError::new(
            ErrorCode::InvalidUriPath,
            "External key identifier is not valid in an XKS URI",
        ));
    }
    if request.encryption_algorithm != "AES_GCM" {
        return error_response(invalid_request());
    }
    let mut plaintext_b64 = std::mem::take(&mut request.plaintext);
    let decoded_plaintext = STANDARD.decode(&plaintext_b64);
    plaintext_b64.zeroize();
    let plaintext = match decoded_plaintext {
        Ok(v) if v.len() <= MAX_PLAINTEXT => v,
        _ => return error_response(invalid_request()),
    };
    let plaintext = Zeroizing::new(plaintext);
    let aad = match decode_optional(request.additional_authenticated_data.as_deref(), MAX_AAD) {
        Ok(v) => v,
        Err(e) => return error_response(e),
    };
    if request
        .ciphertext_data_integrity_value_algorithm
        .as_deref()
        .is_some_and(|v| v != "SHA_256")
    {
        return error_response(invalid_request());
    }
    let provider = state.provider.clone();
    let key_for_call = key.clone();
    let request_metadata = request.request_metadata;
    tracing::info!(
        external_key_id = %key,
        kms_request_id = request_metadata.kms_request_id.as_deref().unwrap_or("unknown"),
        kms_operation = request_metadata.kms_operation.as_deref().unwrap_or("unknown"),
        "XKS Encrypt request"
    );
    if request_metadata.aws_principal_arn.is_none()
        || request_metadata.kms_key_arn.is_none()
        || request_metadata.kms_operation.is_none()
        || request_metadata.kms_request_id.is_none()
    {
        return error_response(invalid_request());
    }
    let result = run_provider(&state, move || {
        let output =
            provider.encrypt(&key_for_call, plaintext.as_slice(), &aad, &request_metadata)?;
        if output.ciphertext.len() != plaintext.len()
            || !(output.initialization_vector.len() == 12
                || output.initialization_vector.len() == 16)
            || output.authentication_tag.len() != 16
            || output.ciphertext_metadata.len() > 20
        {
            return Err(XksError::new(
                ErrorCode::Internal,
                "Key manager returned an invalid AES-GCM result",
            ));
        }
        let cdiv = if request.ciphertext_data_integrity_value_algorithm.is_some() {
            Some(compute_cdiv(
                &aad,
                &output.ciphertext_metadata,
                &output.initialization_vector,
                &output.ciphertext,
                &output.authentication_tag,
            ))
        } else {
            None
        };
        // AWS Appendix C requires computing CDIV before a decrypt round-trip.
        if cdiv.is_some() {
            let check = Zeroizing::new(provider.decrypt(
                &key_for_call,
                ProviderDecryptRequest {
                    ciphertext: &output.ciphertext,
                    initialization_vector: &output.initialization_vector,
                    authentication_tag: &output.authentication_tag,
                    ciphertext_metadata: &output.ciphertext_metadata,
                    additional_authenticated_data: &aad,
                    request_metadata: &request_metadata,
                },
            )?);
            if check.as_slice() != plaintext.as_slice() {
                return Err(XksError::new(
                    ErrorCode::Internal,
                    "Encrypt/decrypt integrity round-trip failed",
                ));
            }
        }
        Ok(EncryptResponse {
            ciphertext: STANDARD.encode(output.ciphertext),
            ciphertext_metadata: if output.ciphertext_metadata.is_empty() {
                None
            } else {
                Some(STANDARD.encode(output.ciphertext_metadata))
            },
            initialization_vector: STANDARD.encode(output.initialization_vector),
            authentication_tag: STANDARD.encode(output.authentication_tag),
            ciphertext_data_integrity_value: cdiv,
        })
    })
    .await;
    match result {
        Ok(response) => Json(response).into_response(),
        Err(error) => error_response(error),
    }
}
async fn decrypt(State(state): State<AppState>, Path(key): Path<String>, body: Bytes) -> Response {
    let request: DecryptRequest = match parse_request(&body) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    if !valid_key_id(&key) {
        return error_response(XksError::new(
            ErrorCode::InvalidUriPath,
            "External key identifier is not valid in an XKS URI",
        ));
    }
    if request.encryption_algorithm != "AES_GCM" {
        return error_response(invalid_request());
    }
    let ciphertext = match STANDARD.decode(request.ciphertext) {
        Ok(v) if v.len() <= MAX_PLAINTEXT => v,
        _ => return error_response(invalid_request()),
    };
    let iv = match STANDARD.decode(request.initialization_vector) {
        Ok(v) if v.len() == 12 || v.len() == 16 => v,
        _ => return error_response(invalid_request()),
    };
    let tag = match STANDARD.decode(request.authentication_tag) {
        Ok(v) if v.len() == 16 => v,
        _ => return error_response(invalid_request()),
    };
    let metadata = match decode_optional(request.ciphertext_metadata.as_deref(), 20) {
        Ok(v) => v,
        Err(e) => return error_response(e),
    };
    let aad = match decode_optional(request.additional_authenticated_data.as_deref(), MAX_AAD) {
        Ok(v) => v,
        Err(e) => return error_response(e),
    };
    let provider = state.provider.clone();
    let request_metadata = request.request_metadata;
    tracing::info!(
        external_key_id = %key,
        kms_request_id = request_metadata.kms_request_id.as_deref().unwrap_or("unknown"),
        kms_operation = request_metadata.kms_operation.as_deref().unwrap_or("unknown"),
        "XKS Decrypt request"
    );
    if request_metadata.aws_principal_arn.is_none()
        || request_metadata.kms_key_arn.is_none()
        || request_metadata.kms_operation.is_none()
        || request_metadata.kms_request_id.is_none()
    {
        return error_response(invalid_request());
    }
    let ciphertext_len = ciphertext.len();
    match run_provider(&state, move || {
        provider.decrypt(
            &key,
            ProviderDecryptRequest {
                ciphertext: &ciphertext,
                initialization_vector: &iv,
                authentication_tag: &tag,
                ciphertext_metadata: &metadata,
                additional_authenticated_data: &aad,
                request_metadata: &request_metadata,
            },
        )
    })
    .await
    {
        Ok(plaintext) if plaintext.len() == ciphertext_len && plaintext.len() <= MAX_PLAINTEXT => {
            let plaintext = Zeroizing::new(plaintext);
            Json(DecryptResponse {
                plaintext: STANDARD.encode(plaintext.as_slice()),
            })
            .into_response()
        }
        Ok(_) => error_response(XksError::new(
            ErrorCode::InvalidCiphertext,
            "Key manager returned an invalid plaintext length",
        )),
        Err(error) => error_response(error),
    }
}

async fn run_provider<T, F>(state: &AppState, operation: F) -> Result<T, XksError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, XksError> + Send + 'static,
{
    let permit = state
        .provider_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| XksError::new(ErrorCode::Throttling, "External key manager is at capacity"))?;
    let worker = task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    });
    match tokio::time::timeout(Duration::from_millis(225), worker).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(XksError::new(
            ErrorCode::Internal,
            "External key manager task failed",
        )),
        Err(_) => Err(XksError::new(
            ErrorCode::DependencyTimeout,
            "External key manager operation timed out",
        )),
    }
}

fn parse_request<T: DeserializeOwned>(body: &[u8]) -> Result<T, XksError> {
    serde_json::from_slice(body).map_err(|_| invalid_request())
}

fn compute_cdiv(aad: &[u8], metadata: &[u8], iv: &[u8], ciphertext: &[u8], tag: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(aad);
    hasher.update(metadata);
    hasher.update(iv);
    hasher.update(ciphertext);
    hasher.update(tag);
    STANDARD.encode(hasher.finalize())
}

fn decode_optional(value: Option<&str>, max: usize) -> Result<Vec<u8>, XksError> {
    match value {
        Some(v) => STANDARD
            .decode(v)
            .ok()
            .filter(|b| b.len() <= max)
            .ok_or_else(invalid_request),
        None => Ok(Vec::new()),
    }
}
fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}
fn invalid_request() -> XksError {
    XksError::new(ErrorCode::InvalidRequest, "Invalid XKS v1 request")
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    error_name: &'static str,
    error_message: String,
}
fn error_response(error: XksError) -> Response {
    let status = match error.code {
        ErrorCode::AuthenticationFailed => StatusCode::UNAUTHORIZED,
        ErrorCode::AccessDenied => StatusCode::FORBIDDEN,
        ErrorCode::InvalidKey | ErrorCode::InvalidUriPath => StatusCode::NOT_FOUND,
        ErrorCode::Throttling => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::InvalidCiphertext
        | ErrorCode::InvalidKeyUsage
        | ErrorCode::InvalidState
        | ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
        ErrorCode::UnsupportedOperation => StatusCode::NOT_IMPLEMENTED,
        ErrorCode::DependencyTimeout | ErrorCode::DependencyUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let message: String = error
        .message
        .chars()
        .filter(|c| (' '..='~').contains(c))
        .take(511)
        .collect();
    (
        status,
        Json(ErrorBody {
            error_name: error.code.as_str(),
            error_message: message,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{XksProxyConfig, compute_cdiv, parse_request};
    use crate::{
        SigV4Credential,
        protocol::{ErrorCode, GetHealthStatusRequest},
    };
    use zeroize::Zeroizing;

    #[test]
    fn validates_proxy_path_and_sigv4_credential_shape() {
        let config = XksProxyConfig {
            uri_path: "/tenant-a/kms/xks/v1".into(),
            access_key_id: "ABCDEFGHIJKLMNOPQRST".into(),
            secret_access_key: Zeroizing::new("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".into()),
            additional_credentials: Vec::new(),
        };
        assert!(config.validate().is_ok());
        let invalid = XksProxyConfig {
            uri_path: "/kms/xks/v1?query=1".into(),
            ..config
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn malformed_json_maps_to_xks_validation_error() {
        let error = parse_request::<GetHealthStatusRequest>(b"not-json").unwrap_err();
        assert!(matches!(error.code, ErrorCode::InvalidRequest));
    }

    #[test]
    fn validates_all_sigv4_credential_and_path_constraints() {
        let base = XksProxyConfig {
            uri_path: "/kms/xks/v1".into(),
            access_key_id: "ABCDEFGHIJKLMNOPQRST".into(),
            secret_access_key: Zeroizing::new("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".into()),
            additional_credentials: Vec::new(),
        };
        assert!(base.validate().is_ok());
        assert!(
            XksProxyConfig {
                access_key_id: "short".into(),
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            XksProxyConfig {
                secret_access_key: Zeroizing::new("short".into()),
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            XksProxyConfig {
                uri_path: "/kms/xks/v1/".into(),
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            XksProxyConfig {
                uri_path: "/kms/xks/v1?x=1".into(),
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        let duplicate = SigV4Credential {
            access_key_id: base.access_key_id.clone(),
            secret_access_key: base.secret_access_key.clone(),
        };
        assert!(
            XksProxyConfig {
                additional_credentials: vec![duplicate],
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        let second = SigV4Credential {
            access_key_id: "QRSTUVWXYZABCDEFGHIJ".into(),
            secret_access_key: Zeroizing::new("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".into()),
        };
        assert!(
            XksProxyConfig {
                additional_credentials: vec![second.clone(), second],
                ..base
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn decodes_optional_base64_with_size_limits() {
        use super::decode_optional;
        assert_eq!(decode_optional(None, 4).unwrap(), Vec::<u8>::new());
        assert_eq!(decode_optional(Some("YWJj"), 4).unwrap(), b"abc");
        assert!(decode_optional(Some("%%%"), 4).is_err());
        assert!(decode_optional(Some("YWJjZA=="), 3).is_err());
    }

    #[test]
    fn validates_external_key_identifiers() {
        use super::valid_key_id;
        assert!(valid_key_id("key-01.test_name"));
        assert!(!valid_key_id(""));
        assert!(!valid_key_id("bad/key"));
        assert!(!valid_key_id(&"a".repeat(129)));
    }

    #[test]
    fn maps_xks_errors_to_expected_http_statuses() {
        use super::error_response;
        use crate::protocol::XksError;
        use axum::http::StatusCode;
        let cases = [
            (ErrorCode::AuthenticationFailed, StatusCode::UNAUTHORIZED),
            (ErrorCode::AccessDenied, StatusCode::FORBIDDEN),
            (ErrorCode::InvalidKey, StatusCode::NOT_FOUND),
            (ErrorCode::Throttling, StatusCode::TOO_MANY_REQUESTS),
            (ErrorCode::InvalidCiphertext, StatusCode::BAD_REQUEST),
            (ErrorCode::UnsupportedOperation, StatusCode::NOT_IMPLEMENTED),
            (
                ErrorCode::DependencyTimeout,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (ErrorCode::Internal, StatusCode::INTERNAL_SERVER_ERROR),
        ];
        for (code, expected) in cases {
            assert_eq!(
                error_response(XksError::new(code, "safe message")).status(),
                expected
            );
        }
    }

    #[test]
    fn cdiv_matches_the_aws_xks_v1_example() {
        let aad = b"project=nile,department=marketing";
        let metadata = b"key_version=1";
        let iv = [
            0x1c, 0xca, 0xe5, 0x47, 0x0f, 0x39, 0x70, 0x02, 0x54, 0x77, 0x90, 0x31,
        ];
        let ciphertext = [
            0x82, 0x1c, 0x64, 0x2b, 0x5b, 0x71, 0x78, 0x33, 0x67, 0xde, 0xaf, 0x18,
        ];
        let tag = [
            0xbc, 0x1c, 0x4d, 0xda, 0x77, 0x07, 0xd6, 0x81, 0x24, 0x47, 0xc5, 0x95, 0x5e, 0x99,
            0xb2, 0x61,
        ];
        assert_eq!(
            compute_cdiv(aad, metadata, &iv, &ciphertext, &tag),
            "qHA/ImC9h5HsLRXqCyPmWgYx7tzyoTplzILbP0fPXsc="
        );
    }
}

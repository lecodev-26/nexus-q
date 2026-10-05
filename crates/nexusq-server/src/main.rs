//! `nexusq-server` — authenticated HTTP service for NEXUS-Q.

use std::{
    env,
    net::SocketAddr,
    path::PathBuf,
    result::Result as StdResult,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nexusq_core::{
    Metrics,
    crypto::sign::Signature,
    prelude::*,
    vault::{DestructionConfirmation, RevokeReason},
};
use serde::Serialize;
use tokio::sync::Mutex;
use tower::ServiceBuilder;

const DEFAULT_ADDR: &str = "127.0.0.1:8443";
const DEFAULT_RATE_LIMIT: u32 = 60;
const SESSION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MIN_SERVER_TOKEN_BYTES: usize = 32;

#[derive(Clone)]
struct AppState {
    vault: Arc<Mutex<ServerVault>>,
    auth: Arc<AuthConfig>,
    limiter: Arc<RateLimiter>,
    max_request_body_bytes: usize,
    metrics: Metrics,
}

struct ServerVault {
    vault: Vault,
    session: Option<Session>,
    last_activity: Option<Instant>,
}

struct AuthConfig {
    bearer_token: String,
}

struct ServerConfig {
    vault_path: PathBuf,
    server_token: String,
    addr: SocketAddr,
    rate_limit: u32,
    max_request_body_bytes: usize,
    trusted_tls_termination: bool,
}

impl ServerConfig {
    fn from_env() -> StdResult<Self, Box<dyn std::error::Error>> {
        let vault_path = env::var_os("NEXUSQ_VAULT_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| std::io::Error::other("NEXUSQ_VAULT_PATH is required"))?;

        let server_token = env::var("NEXUSQ_SERVER_TOKEN").map_err(|_| {
            std::io::Error::other(
                "NEXUSQ_SERVER_TOKEN is required; server refuses unauthenticated startup",
            )
        })?;
        if server_token.len() < MIN_SERVER_TOKEN_BYTES {
            return Err(
                std::io::Error::other("NEXUSQ_SERVER_TOKEN must be at least 32 bytes").into(),
            );
        }

        let addr = env::var("NEXUSQ_SERVER_ADDR")
            .unwrap_or_else(|_| DEFAULT_ADDR.into())
            .parse::<SocketAddr>()
            .map_err(|_| {
                std::io::Error::other("NEXUSQ_SERVER_ADDR must be a valid socket address")
            })?;

        let rate_limit = parse_positive_u32("NEXUSQ_SERVER_RATE_LIMIT", DEFAULT_RATE_LIMIT)?;
        let max_request_body_bytes =
            parse_positive_usize("NEXUSQ_SERVER_MAX_BODY_BYTES", MAX_REQUEST_BODY_BYTES)?;
        let trusted_tls_termination = env::var("NEXUSQ_TRUSTED_TLS_TERMINATION")
            .map(|value| value == "1")
            .unwrap_or(false);

        if !addr.ip().is_loopback() && !trusted_tls_termination {
            return Err(std::io::Error::other(
                "non-loopback TCP requires NEXUSQ_TRUSTED_TLS_TERMINATION=1; plaintext remote exposure is refused",
            )
            .into());
        }

        Ok(Self {
            vault_path,
            server_token,
            addr,
            rate_limit,
            max_request_body_bytes,
            trusted_tls_termination,
        })
    }
}

fn parse_positive_u32_value(value: &str) -> StdResult<u32, Box<dyn std::error::Error>> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| std::io::Error::other("value must be a positive integer"))?;
    if parsed == 0 {
        return Err(std::io::Error::other("value must be greater than zero").into());
    }
    Ok(parsed)
}

fn parse_positive_u32(name: &str, default: u32) -> StdResult<u32, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => parse_positive_u32_value(&value).map_err(|_| {
            std::io::Error::other(format!("{name} must be a positive integer")).into()
        }),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => {
            Err(std::io::Error::other(format!("{name} must be valid UTF-8")).into())
        }
    }
}

fn parse_positive_usize_value(value: &str) -> StdResult<usize, Box<dyn std::error::Error>> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| std::io::Error::other("value must be a positive integer"))?;
    if parsed == 0 {
        return Err(std::io::Error::other("value must be greater than zero").into());
    }
    Ok(parsed)
}

fn parse_positive_usize(
    name: &str,
    default: usize,
) -> StdResult<usize, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => parse_positive_usize_value(&value).map_err(|_| {
            std::io::Error::other(format!("{name} must be a positive integer")).into()
        }),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => {
            Err(std::io::Error::other(format!("{name} must be valid UTF-8")).into())
        }
    }
}

struct RateLimiter {
    window: Duration,
    max_requests: u32,
    entries: std::sync::Mutex<std::collections::HashMap<String, (Instant, u32)>>,
}

#[derive(Serialize)]
struct StatusResponse {
    state: &'static str,
    path: String,
}

#[derive(Serialize)]
struct VersionResponse {
    version: &'static str,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct ReadinessResponse {
    status: &'static str,
    vault: &'static str,
}

#[derive(serde::Deserialize)]
struct UnlockRequest {
    password: String,
}

#[derive(serde::Deserialize)]
struct EncryptRequest {
    key_id: String,
    plaintext: String,
    metadata: Option<String>,
}

#[derive(serde::Deserialize)]
struct DecryptRequest {
    envelope: String,
}

#[derive(serde::Deserialize)]
struct SignRequest {
    identity_id: String,
    message: String,
}

#[derive(serde::Deserialize)]
struct VerifyRequest {
    identity_id: String,
    message: String,
    signature: String,
}

#[derive(serde::Deserialize)]
struct CreateKeyRequest {
    algorithm: String,
    purpose: String,
}

#[derive(serde::Deserialize)]
struct RevokeKeyRequest {
    reason: Option<String>,
}

#[derive(Serialize)]
struct KeyResponse {
    key_id: String,
    algorithm: String,
    purpose: String,
    status: String,
}

#[derive(Serialize)]
struct DataResponse {
    data: String,
}

#[derive(Serialize)]
struct AuditResponse {
    verified: bool,
    current_segment_events: Vec<nexusq_core::storage::AuditEvent>,
}

#[tokio::main]
async fn main() -> StdResult<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "nexusq_server=info".into()))
        .init();

    let config = ServerConfig::from_env()?;
    let vault = Vault::open(&config.vault_path)?;

    let state = AppState {
        vault: Arc::new(Mutex::new(ServerVault {
            vault,
            session: None,
            last_activity: None,
        })),
        auth: Arc::new(AuthConfig {
            bearer_token: config.server_token,
        }),
        limiter: Arc::new(RateLimiter::new(config.rate_limit, Duration::from_secs(60))),
        max_request_body_bytes: config.max_request_body_bytes,
        metrics: Metrics::default(),
    };

    let app = build_app(state);

    tracing::info!(
        addr = %config.addr,
        rate_limit = config.rate_limit,
        max_request_body_bytes = config.max_request_body_bytes,
        trusted_tls_termination = config.trusted_tls_termination,
        "nexusq-server listening"
    );
    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn build_app(state: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/health", get(health))
        .route("/v1/ready", get(ready))
        .route("/v1/version", get(version));

    let protected = Router::new()
        .route("/v1/vault/unlock", post(unlock))
        .route("/v1/vault/lock", post(lock))
        .route("/v1/vault/status", get(status))
        .route("/v1/keys", get(list_keys).post(create_key))
        .route("/v1/keys/{key_id}/rotate", post(rotate_key))
        .route("/v1/keys/{key_id}/revoke", post(revoke_key))
        .route("/v1/keys/{key_id}/destroy", post(destroy_key))
        .route("/v1/encrypt", post(encrypt))
        .route("/v1/decrypt", post(decrypt))
        .route("/v1/sign", post(sign))
        .route("/v1/verify", post(verify))
        .route("/v1/audit", get(audit))
        .route("/v1/audit/verify", post(verify_audit))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session_timeout_middleware,
        ));

    public
        .merge(protected)
        .layer(DefaultBodyLimit::max(state.max_request_body_bytes))
        .layer(ServiceBuilder::new().layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        )))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            observability_middleware,
        ))
        .with_state(state)
}

impl RateLimiter {
    fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            window,
            max_requests,
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn allow(&self, client: &str) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("rate limiter mutex poisoned");
        let entry = entries.entry(client.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 1);
            return true;
        }
        if entry.1 >= self.max_requests {
            return false;
        }
        entry.1 += 1;
        true
    }
}

async fn observability_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let request_id = state.metrics.request_id();
    let operation = operation_name(request.uri().path());
    request.extensions_mut().insert(request_id.clone());
    let started = Instant::now();
    tracing::info!(request_id = %request_id, operation, "request started");

    let mut response = next.run(request).await;
    let elapsed = started.elapsed();
    let success = response.status().is_success();
    state.metrics.record_request(elapsed, success);
    state.metrics.record_operation(operation, elapsed, success);
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-request-id"),
        axum::http::HeaderValue::from_str(&request_id).expect("request id is valid ASCII"),
    );
    tracing::info!(
        request_id = %request_id,
        operation,
        status = response.status().as_u16(),
        duration_ms = elapsed.as_secs_f64() * 1000.0,
        "request finished"
    );
    response
}

fn operation_name(path: &str) -> &'static str {
    match path {
        "/health" | "/v1/health" => "health.check",
        "/readyz" | "/v1/ready" => "health.ready",
        "/metrics" => "observability.metrics",
        "/v1/version" => "server.version",
        "/v1/vault/unlock" => "vault.unlock",
        "/v1/vault/lock" => "vault.lock",
        "/v1/vault/status" => "vault.status",
        "/v1/keys" => "key.list_or_create",
        "/v1/encrypt" => "crypto.encrypt",
        "/v1/decrypt" => "crypto.decrypt",
        "/v1/sign" => "identity.sign",
        "/v1/verify" => "identity.verify",
        "/v1/audit" => "vault.audit",
        "/v1/audit/verify" => "vault.audit_verify",
        path if path.contains("/rotate") => "key.rotate",
        path if path.contains("/revoke") => "key.revoke",
        path if path.contains("/destroy") => "key.destroy",
        _ => "http.other",
    }
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let client = if env::var("NEXUSQ_TRUSTED_TLS_TERMINATION").as_deref() == Ok("1") {
        request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("proxy")
            .split(',')
            .next()
            .unwrap_or("proxy")
            .trim()
    } else {
        "local"
    };
    if !state.limiter.allow(client) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    next.run(request).await
}

async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let authorized = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|value| is_bearer_authorized(value, &state.auth.bearer_token))
        .unwrap_or(false);
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    }
    next.run(request).await
}

async fn session_timeout_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    {
        let mut server_vault = state.vault.lock().await;
        if let Some(last_activity) = server_vault.last_activity {
            if last_activity.elapsed() >= SESSION_TIMEOUT {
                if let Some(session) = server_vault.session.take() {
                    match session.lock() {
                        Ok(vault) => {
                            server_vault.vault = vault;
                            server_vault.last_activity = None;
                            tracing::info!("vault session expired due to inactivity");
                        }
                        Err(err) => {
                            server_vault.session = None;
                            server_vault.last_activity = None;
                            tracing::error!(error = %err, "failed to persist expired vault session");
                            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
                                .into_response();
                        }
                    }
                } else {
                    server_vault.last_activity = None;
                }
            }
        }
    }

    let response = next.run(request).await;

    let mut server_vault = state.vault.lock().await;
    if server_vault.session.is_some() {
        server_vault.last_activity = Some(Instant::now());
    }
    response
}

fn is_bearer_authorized(value: &str, expected: &str) -> bool {
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    bool::from(subtle::ConstantTimeEq::ct_eq(
        token.as_bytes(),
        expected.as_bytes(),
    ))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn ready(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let vault = state.vault.lock().await;
    let ready = vault.vault.path().exists();
    let response = ReadinessResponse {
        status: if ready { "ready" } else { "not_ready" },
        vault: if ready { "open" } else { "unavailable" },
    };
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(response),
    )
}

async fn metrics(State(state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.prometheus(),
    )
        .into_response()
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    let vault = state.vault.lock().await;
    let state_name = if vault.session.is_some() {
        "unlocked"
    } else {
        "locked"
    };
    let path = vault.vault.path().display().to_string();
    Json(StatusResponse {
        state: state_name,
        path,
    })
}

async fn unlock(
    State(state): State<AppState>,
    Json(input): Json<UnlockRequest>,
) -> StdResult<StatusCode, ApiError> {
    let mut vault = state.vault.lock().await;
    if vault.session.is_some() {
        return Err(ApiError::Conflict);
    }
    let session = vault
        .vault
        .unlock(input.password.as_bytes())
        .map_err(|err| ApiError::Core(err.into()))?;
    vault.session = Some(session);
    vault.last_activity = Some(Instant::now());
    Ok(StatusCode::NO_CONTENT)
}

async fn lock(State(state): State<AppState>) -> StdResult<StatusCode, ApiError> {
    let mut vault = state.vault.lock().await;
    let Some(session) = vault.session.take() else {
        return Err(ApiError::Conflict);
    };
    vault.last_activity = None;
    match session.lock() {
        Ok(locked) => {
            vault.vault = locked;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(err) => {
            vault.session = None;
            Err(ApiError::Core(err.into()))
        }
    }
}

async fn list_keys(State(state): State<AppState>) -> StdResult<Json<Vec<KeyResponse>>, ApiError> {
    let vault = state.vault.lock().await;
    let Some(session) = vault.session.as_ref() else {
        return Err(ApiError::Locked);
    };
    let keys = session
        .list_keys()
        .map(|key| KeyResponse {
            key_id: key.key_id().to_string(),
            algorithm: key.algorithm().as_str().to_string(),
            purpose: key.purpose().as_str().to_string(),
            status: key.status().to_string(),
        })
        .collect();
    Ok(Json(keys))
}

async fn create_key(
    State(state): State<AppState>,
    Json(input): Json<CreateKeyRequest>,
) -> StdResult<Json<KeyResponse>, ApiError> {
    let mut vault = state.vault.lock().await;
    let Some(session) = vault.session.as_mut() else {
        return Err(ApiError::Locked);
    };
    let algorithm = input
        .algorithm
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid algorithm"))?;
    let purpose = input
        .purpose
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid purpose"))?;
    let key_id = session
        .generate_key(algorithm, purpose)
        .map_err(|err| ApiError::Core(err.into()))?;
    let key = session.find_key(&key_id).ok_or(ApiError::Internal)?;
    Ok(Json(KeyResponse {
        key_id: key.key_id().to_string(),
        algorithm: key.algorithm().as_str().to_string(),
        purpose: key.purpose().as_str().to_string(),
        status: key.status().to_string(),
    }))
}

async fn rotate_key(
    State(state): State<AppState>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
) -> StdResult<Json<DataResponse>, ApiError> {
    let mut vault = state.vault.lock().await;
    let Some(session) = vault.session.as_mut() else {
        return Err(ApiError::Locked);
    };
    let key_id = key_id
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid key_id"))?;
    let new_id = session
        .rotate_key(&key_id)
        .map_err(|err| ApiError::Core(err.into()))?;
    Ok(Json(DataResponse {
        data: new_id.to_string(),
    }))
}

async fn revoke_key(
    State(state): State<AppState>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
    Json(input): Json<RevokeKeyRequest>,
) -> StdResult<StatusCode, ApiError> {
    let mut vault = state.vault.lock().await;
    let Some(session) = vault.session.as_mut() else {
        return Err(ApiError::Locked);
    };
    let key_id = key_id
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid key_id"))?;
    let reason = match input.reason.as_deref() {
        Some("compromised") => RevokeReason::Compromised,
        Some("superseded") => RevokeReason::Superseded,
        Some("owner_left") => RevokeReason::OwnerLeft,
        Some(value) => RevokeReason::Other(value.to_owned()),
        None => RevokeReason::Other("api-request".to_owned()),
    };
    session
        .revoke_key(&key_id, reason)
        .map_err(|err| ApiError::Core(err.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn destroy_key(
    State(state): State<AppState>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
) -> StdResult<StatusCode, ApiError> {
    let mut vault = state.vault.lock().await;
    let Some(session) = vault.session.as_mut() else {
        return Err(ApiError::Locked);
    };
    let key_id = key_id
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid key_id"))?;
    session
        .destroy_key(&key_id, DestructionConfirmation::Explicit)
        .map_err(|err| ApiError::Core(err.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn encrypt(
    State(state): State<AppState>,
    Json(input): Json<EncryptRequest>,
) -> StdResult<Json<DataResponse>, ApiError> {
    let vault = state.vault.lock().await;
    let Some(session) = vault.session.as_ref() else {
        return Err(ApiError::Locked);
    };
    let key_id: KeyId = input
        .key_id
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid key_id"))?;
    let plaintext = input.plaintext.into_bytes();
    let metadata = input.metadata.unwrap_or_default().into_bytes();
    let envelope = session
        .encrypt(&key_id, &plaintext, metadata)
        .map_err(|err| ApiError::Core(err.into()))?;
    Ok(Json(DataResponse {
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, envelope),
    }))
}

async fn sign(
    State(state): State<AppState>,
    Json(input): Json<SignRequest>,
) -> StdResult<Json<DataResponse>, ApiError> {
    let vault = state.vault.lock().await;
    let Some(session) = vault.session.as_ref() else {
        return Err(ApiError::Locked);
    };
    let identity_id = input
        .identity_id
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid identity_id"))?;
    let signature = session
        .identity_sign(&identity_id, input.message.as_bytes())
        .map_err(|err| ApiError::Core(err.into()))?;
    Ok(Json(DataResponse {
        data: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature.to_bytes().as_slice(),
        ),
    }))
}

async fn verify(
    State(state): State<AppState>,
    Json(input): Json<VerifyRequest>,
) -> StdResult<StatusCode, ApiError> {
    let vault = state.vault.lock().await;
    let Some(session) = vault.session.as_ref() else {
        return Err(ApiError::Locked);
    };
    let identity_id = input
        .identity_id
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid identity_id"))?;
    let signature_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input.signature)
            .map_err(|_| ApiError::BadRequest("invalid signature encoding"))?;
    let signature = Signature::from_bytes(&signature_bytes)
        .map_err(|_| ApiError::BadRequest("invalid signature"))?;
    session
        .identity_verify(&identity_id, input.message.as_bytes(), &signature)
        .map_err(|err| ApiError::Core(err.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn audit(State(state): State<AppState>) -> StdResult<Json<AuditResponse>, ApiError> {
    let vault = state.vault.lock().await;
    let Some(session) = vault.session.as_ref() else {
        return Err(ApiError::Locked);
    };
    let events = session.audit_events().unwrap_or_default();
    let verified = session.verify_audit().is_ok();
    Ok(Json(AuditResponse {
        verified,
        current_segment_events: events,
    }))
}

async fn verify_audit(State(state): State<AppState>) -> StdResult<StatusCode, ApiError> {
    let vault = state.vault.lock().await;
    let Some(session) = vault.session.as_ref() else {
        return Err(ApiError::Locked);
    };
    session
        .verify_audit()
        .map_err(|err| ApiError::Core(err.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn decrypt(
    State(state): State<AppState>,
    Json(input): Json<DecryptRequest>,
) -> StdResult<Json<DataResponse>, ApiError> {
    let vault = state.vault.lock().await;
    let Some(session) = vault.session.as_ref() else {
        return Err(ApiError::Locked);
    };
    let envelope =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input.envelope)
            .map_err(|_| ApiError::BadRequest("invalid envelope encoding"))?;
    let plaintext = session
        .decrypt(&envelope)
        .map_err(|err| ApiError::Core(err.into()))?;
    Ok(Json(DataResponse {
        data: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            plaintext.as_slice(),
        ),
    }))
}

#[derive(Debug)]
enum ApiError {
    Core(nexusq_core::Error),
    Locked,
    Conflict,
    BadRequest(&'static str),
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Core(err) => {
                tracing::warn!(error = %err, "NEXUS-Q operation failed");
                (StatusCode::BAD_REQUEST, "operation failed")
            }
            Self::Locked => (StatusCode::LOCKED, "vault is locked"),
            Self::Conflict => (StatusCode::CONFLICT, "invalid vault state"),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
        };
        (status, message).into_response()
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(error) => {
                    tracing::warn!(%error, "failed to install SIGTERM handler; waiting for SIGINT");
                    let _ = tokio::signal::ctrl_c().await;
                    tracing::info!("shutdown signal received");
                    return;
                }
            };

        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "failed to receive SIGINT");
                }
            }
            _ = terminate.recv() => {
                tracing::info!("SIGTERM received");
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "failed to receive shutdown signal");
        }
    }

    tracing::info!("graceful shutdown initiated");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_integer_parsers_have_safe_defaults_and_reject_invalid_values() {
        assert_eq!(parse_positive_u32("NEXUSQ_TEST_MISSING", 60).unwrap(), 60);
        assert!(parse_positive_u32_value("0").is_err());
        assert!(parse_positive_u32_value("not-a-number").is_err());
        assert_eq!(parse_positive_u32_value("7").unwrap(), 7);

        assert_eq!(parse_positive_usize_value("1024").unwrap(), 1024);
        assert!(parse_positive_usize_value("0").is_err());
        assert!(parse_positive_usize_value("not-a-number").is_err());
    }

    #[test]
    fn server_token_minimum_is_explicit() {
        assert_eq!(MIN_SERVER_TOKEN_BYTES, 32);
    }

    #[test]
    fn bearer_auth_is_exact_and_constant_time() {
        assert!(is_bearer_authorized("Bearer abc123", "abc123"));
        assert!(!is_bearer_authorized("Bearer abc124", "abc123"));
        assert!(!is_bearer_authorized("Basic abc123", "abc123"));
        assert!(!is_bearer_authorized("Bearer ", "abc123"));
    }

    #[test]
    fn rate_limiter_enforces_window_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.allow("client"));
        assert!(limiter.allow("client"));
        assert!(!limiter.allow("client"));
        assert!(limiter.allow("other-client"));
    }

    fn test_state(path: std::path::PathBuf) -> AppState {
        AppState {
            vault: Arc::new(Mutex::new(ServerVault {
                vault: Vault::open(path).unwrap(),
                session: None,
                last_activity: None,
            })),
            auth: Arc::new(AuthConfig {
                bearer_token: "test-token-with-at-least-32-bytes-long".to_owned(),
            }),
            limiter: Arc::new(RateLimiter::new(60, Duration::from_secs(60))),
            max_request_body_bytes: MAX_REQUEST_BODY_BYTES,
            metrics: Metrics::default(),
        }
    }

    #[tokio::test]
    async fn observability_endpoints_expose_safe_metrics_and_request_id() {
        let dir = std::env::temp_dir().join(format!(
            "nexusq-server-observability-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.nqx");
        Vault::create(&vault_path, b"test-password", Some("server-test".into())).unwrap();

        let app = build_app(test_state(vault_path));
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("x-request-id"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("# TYPE nexusq_requests_total counter"));
        assert!(text.contains("nexusq_hardware_status 1"));
        assert!(!text.contains("test-password"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn expired_session_is_locked_before_protected_request() {
        let dir =
            std::env::temp_dir().join(format!("nexusq-server-timeout-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.nqx");
        Vault::create(&vault_path, b"test-password", Some("server-test".into())).unwrap();

        let state = test_state(vault_path.clone());
        {
            let mut server_vault = state.vault.lock().await;
            server_vault.session = Some(server_vault.vault.unlock(b"test-password").unwrap());
            server_vault.last_activity =
                Some(Instant::now() - SESSION_TIMEOUT - Duration::from_secs(1));
        }
        let app = build_app(state);
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/vault/status")
                    .header(
                        "authorization",
                        "Bearer test-token-with-at-least-32-bytes-long",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_health_auth_and_unlock_smoke() {
        use axum::body::Body;
        use axum::http::{Method, Request};
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!("nexusq-server-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("vault.nqx");
        let vault =
            Vault::create(&vault_path, b"test-password", Some("server-test".into())).unwrap();
        drop(vault);

        let app = build_app(test_state(vault_path.clone()));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/vault/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/vault/unlock")
                    .header(
                        "authorization",
                        "Bearer test-token-with-at-least-32-bytes-long",
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"test-password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/vault/status")
                    .header(
                        "authorization",
                        "Bearer test-token-with-at-least-32-bytes-long",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

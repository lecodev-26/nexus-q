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
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nexusq_core::{
    crypto::sign::Signature,
    prelude::*,
    vault::{DestructionConfirmation, RevokeReason},
};
use serde::Serialize;
use tokio::sync::Mutex;
use tower::ServiceBuilder;

const DEFAULT_ADDR: &str = "127.0.0.1:8443";
const DEFAULT_RATE_LIMIT: u32 = 60;

#[derive(Clone)]
struct AppState {
    vault: Arc<Mutex<ServerVault>>,
    auth: Arc<AuthConfig>,
    limiter: Arc<RateLimiter>,
}

struct ServerVault {
    vault: Vault,
    session: Option<Session>,
}

struct AuthConfig {
    bearer_token: String,
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

    let vault_path = env::var_os("NEXUSQ_VAULT_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("NEXUSQ_VAULT_PATH is required"))?;
    let vault = Vault::open(&vault_path)?;
    let token = env::var("NEXUSQ_SERVER_TOKEN").map_err(|_| {
        std::io::Error::other(
            "NEXUSQ_SERVER_TOKEN is required; server refuses unauthenticated startup",
        )
    })?;
    if token.len() < 32 {
        return Err(std::io::Error::other("NEXUSQ_SERVER_TOKEN must be at least 32 bytes").into());
    }

    let state = AppState {
        vault: Arc::new(Mutex::new(ServerVault {
            vault,
            session: None,
        })),
        auth: Arc::new(AuthConfig {
            bearer_token: token,
        }),
        limiter: Arc::new(RateLimiter::new(
            DEFAULT_RATE_LIMIT,
            Duration::from_secs(60),
        )),
    };

    let app = build_app(state);

    let addr: SocketAddr = env::var("NEXUSQ_SERVER_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.into())
        .parse()?;
    if !addr.ip().is_loopback() && env::var("NEXUSQ_TRUSTED_TLS_TERMINATION").as_deref() != Ok("1")
    {
        return Err(std::io::Error::other(
            "non-loopback TCP requires NEXUSQ_TRUSTED_TLS_TERMINATION=1; plaintext remote exposure is refused",
        ).into());
    }
    tracing::info!(%addr, "nexusq-server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn build_app(state: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(health))
        .route("/v1/health", get(health))
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
        ));

    public
        .merge(protected)
        .layer(ServiceBuilder::new().layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        )))
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

async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let client = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("local")
        .split(',')
        .next()
        .unwrap_or("local")
        .trim();
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
    Ok(StatusCode::NO_CONTENT)
}

async fn lock(State(state): State<AppState>) -> StdResult<StatusCode, ApiError> {
    let mut vault = state.vault.lock().await;
    let Some(session) = vault.session.take() else {
        return Err(ApiError::Conflict);
    };
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
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

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
            })),
            auth: Arc::new(AuthConfig {
                bearer_token: "test-token-with-at-least-32-bytes-long".to_owned(),
            }),
            limiter: Arc::new(RateLimiter::new(60, Duration::from_secs(60))),
        }
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

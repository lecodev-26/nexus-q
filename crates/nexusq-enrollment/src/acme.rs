//! ACME RFC 8555 directory, account, order, authorization, challenge, finalize, and certificate routes.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use der::{Decode, EncodePem, pem::LineEnding};
use josekit::{
    jwk::Jwk,
    jws::{ES256, JwsContext, JwsHeader, JwsVerifier, RS256},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_cert::request::CertReq;

use crate::{
    EnrollmentAuthority, Error as EnrollmentError, Principal, Protocol, requested_dns_names,
    suffix_authorizes, valid_dns_name,
};

const MAX_ACME_BODY: usize = 1024 * 1024;
const MAX_ORDER_IDENTIFIERS: usize = 10;
const MAX_ACME_RESOURCES: usize = 100_000;
const NONCE_LIFETIME: Duration = Duration::from_secs(300);

/// Validates ACME challenges using the deployment's DNS/HTTP challenge infrastructure.
/// Implementations must verify the challenge at the public identifier, not merely trust the POST.
#[async_trait]
pub trait AcmeChallengeValidator: Send + Sync {
    /// Return true only when the HTTP-01 or DNS-01 challenge is externally observable and valid.
    async fn validate(
        &self,
        challenge_type: &str,
        identifier: &str,
        token: &str,
        key_authorization: &str,
        dns_txt_value: Option<&str>,
    ) -> bool;
}

#[derive(Clone)]
struct Account {
    id: String,
    jwk: Jwk,
    thumbprint: String,
    contact: Vec<String>,
}
#[derive(Clone)]
struct Order {
    id: String,
    account_id: String,
    identifiers: Vec<String>,
    authorization_ids: Vec<String>,
    status: String,
    certificate_chain: Option<String>,
    expires: u64,
}
#[derive(Clone)]
struct Authorization {
    order_id: String,
    account_id: String,
    identifier: String,
    status: String,
    expires: u64,
    challenge_ids: Vec<String>,
}
#[derive(Clone)]
struct Challenge {
    id: String,
    authorization_id: String,
    account_id: String,
    identifier: String,
    challenge_type: String,
    token: String,
    status: String,
}

struct AcmeState {
    authority: Arc<EnrollmentAuthority>,
    base_url: String,
    validator: Arc<dyn AcmeChallengeValidator>,
    nonces: Mutex<HashMap<String, Instant>>,
    accounts: RwLock<HashMap<String, Account>>,
    orders: RwLock<HashMap<String, Order>>,
    authorizations: RwLock<HashMap<String, Authorization>>,
    challenges: RwLock<HashMap<String, Challenge>>,
    next_id: AtomicU64,
}

#[derive(Debug)]
struct AcmeError {
    status: StatusCode,
    kind: &'static str,
    detail: &'static str,
}
impl AcmeError {
    fn malformed() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            kind: "malformed",
            detail: "The request is malformed or its JWS is invalid.",
        }
    }
    fn bad_nonce() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            kind: "badNonce",
            detail: "The replay nonce is invalid or has already been used.",
        }
    }
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            kind: "unauthorized",
            detail: "The account or request is not authorized.",
        }
    }
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            kind: "malformed",
            detail: "The requested ACME resource was not found.",
        }
    }
    fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            kind: "rateLimited",
            detail: "The enrollment rate limit was exceeded.",
        }
    }
    fn server() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            kind: "serverInternal",
            detail: "The ACME request could not be completed.",
        }
    }
    fn rejected() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            kind: "rejectedIdentifier",
            detail: "The requested identifier or CSR does not satisfy policy.",
        }
    }
    fn response(self) -> Response {
        (self.status, [(header::CONTENT_TYPE, "application/problem+json")], json!({"type": format!("urn:ietf:params:acme:error:{}", self.kind), "detail": self.detail, "status": self.status.as_u16()}).to_string()).into_response()
    }
}

struct VerifiedRequest {
    principal: Principal,
    payload: Value,
    jwk: Jwk,
    account_id: Option<String>,
}

impl EnrollmentAuthority {
    /// Mount an ACME RFC 8555 router. Challenge validation is mandatory and supplied by the host.
    /// The configured `base_url` must be the public HTTPS URL used in ACME protected `url` headers.
    pub fn acme_router(
        self: Arc<Self>,
        base_url: impl Into<String>,
        validator: Arc<dyn AcmeChallengeValidator>,
    ) -> Router {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let state = Arc::new(AcmeState {
            authority: self,
            base_url,
            validator,
            nonces: Mutex::new(HashMap::new()),
            accounts: RwLock::new(HashMap::new()),
            orders: RwLock::new(HashMap::new()),
            authorizations: RwLock::new(HashMap::new()),
            challenges: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        });
        Router::new()
            .route("/acme/{*path}", any(dispatch))
            .route("/acme", any(dispatch))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_ACME_BODY))
            .with_state(state)
    }
}

async fn dispatch(
    State(state): State<Arc<AcmeState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_owned();
    let response = if method == Method::GET && path == "/acme/directory" {
        json_response(
            StatusCode::OK,
            json!({
                "newNonce": format!("{}/acme/new-nonce", state.base_url),
                "newAccount": format!("{}/acme/new-account", state.base_url),
                "newOrder": format!("{}/acme/new-order", state.base_url),
                "meta": {"termsOfService": format!("{}/acme/terms", state.base_url), "externalAccountRequired": false}
            }),
        )
    } else if method == Method::GET && path == "/acme/terms" {
        (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "NexusQ ACME terms: requests are authenticated, policy-checked and audited. By using this endpoint you agree to authorized certificate issuance only.").into_response()
    } else if (method == Method::HEAD || method == Method::GET) && path == "/acme/new-nonce" {
        Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    } else if method != Method::POST
        || body.len() > MAX_ACME_BODY
        || !headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|value| value.starts_with("application/jose+json"))
    {
        AcmeError::malformed().response()
    } else {
        match handle_post(&state, &path, &body).await {
            Ok(response) => response,
            Err(error) => error.response(),
        }
    };
    add_response_headers(&state, response)
}

fn add_response_headers(state: &AcmeState, mut response: Response) -> Response {
    if let Ok(nonce) = state.fresh_nonce() {
        if let Ok(value) = HeaderValue::from_str(&nonce) {
            response.headers_mut().insert("Replay-Nonce", value);
        }
    }
    if let Ok(value) = HeaderValue::from_str(&format!(
        "<{}/acme/directory>;rel=\"index\"",
        state.base_url
    )) {
        response.headers_mut().insert(header::LINK, value);
    }
    response
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

impl AcmeState {
    fn next_id(&self, prefix: &str) -> String {
        format!(
            "{prefix}-{:016x}",
            self.next_id.fetch_add(1, Ordering::SeqCst)
        )
    }
    fn fresh_nonce(&self) -> Result<String, AcmeError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| AcmeError::server())?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let now = Instant::now();
        let mut nonces = self.nonces.lock().map_err(|_| AcmeError::server())?;
        nonces.retain(|_, created| now.duration_since(*created) <= NONCE_LIFETIME);
        if nonces.len() >= 10_000 {
            if let Some(oldest) = nonces
                .iter()
                .min_by_key(|(_, created)| *created)
                .map(|(token, _)| token.clone())
            {
                nonces.remove(&oldest);
            }
        }
        nonces.insert(token.clone(), now);
        Ok(token)
    }
    fn consume_nonce(&self, nonce: &str) -> Result<(), AcmeError> {
        let mut nonces = self.nonces.lock().map_err(|_| AcmeError::server())?;
        match nonces.remove(nonce) {
            Some(created) if created.elapsed() <= NONCE_LIFETIME => Ok(()),
            _ => Err(AcmeError::bad_nonce()),
        }
    }
}

fn public_jwk(jwk: &Jwk) -> Result<(), AcmeError> {
    let value = serde_json::to_value(jwk).map_err(|_| AcmeError::malformed())?;
    let object = value.as_object().ok_or_else(AcmeError::malformed)?;
    for private_member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        if object.contains_key(private_member) {
            return Err(AcmeError::malformed());
        }
    }
    Ok(())
}

fn thumbprint(jwk: &Jwk) -> Result<String, AcmeError> {
    public_jwk(jwk)?;
    let value = serde_json::to_value(jwk).map_err(|_| AcmeError::malformed())?;
    let kty = value
        .get("kty")
        .and_then(Value::as_str)
        .ok_or_else(AcmeError::malformed)?;
    let canonical = match kty {
        "EC" => {
            let crv = value
                .get("crv")
                .and_then(Value::as_str)
                .ok_or_else(AcmeError::malformed)?;
            let x = value
                .get("x")
                .and_then(Value::as_str)
                .ok_or_else(AcmeError::malformed)?;
            let y = value
                .get("y")
                .and_then(Value::as_str)
                .ok_or_else(AcmeError::malformed)?;
            if crv != "P-256" {
                return Err(AcmeError::malformed());
            }
            json!({"crv":crv,"kty":"EC","x":x,"y":y})
        }
        "RSA" => {
            let e = value
                .get("e")
                .and_then(Value::as_str)
                .ok_or_else(AcmeError::malformed)?;
            let n = value
                .get("n")
                .and_then(Value::as_str)
                .ok_or_else(AcmeError::malformed)?;
            let modulus = URL_SAFE_NO_PAD
                .decode(n)
                .map_err(|_| AcmeError::malformed())?;
            if modulus.len() < 256 {
                return Err(AcmeError::malformed());
            }
            json!({"e":e,"kty":"RSA","n":n})
        }
        _ => return Err(AcmeError::malformed()),
    };
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(
        serde_json::to_vec(&canonical).map_err(|_| AcmeError::malformed())?,
    )))
}

fn verifier(algorithm: Option<&str>, jwk: &Jwk) -> Result<Box<dyn JwsVerifier>, AcmeError> {
    match algorithm {
        Some("ES256") => Ok(Box::new(
            ES256
                .verifier_from_jwk(jwk)
                .map_err(|_| AcmeError::malformed())?,
        )),
        Some("RS256") => Ok(Box::new(
            RS256
                .verifier_from_jwk(jwk)
                .map_err(|_| AcmeError::malformed())?,
        )),
        _ => Err(AcmeError::malformed()),
    }
}

fn verify_jws(
    state: &AcmeState,
    path: &str,
    body: &[u8],
    allow_jwk: bool,
) -> Result<VerifiedRequest, AcmeError> {
    let envelope: Value = serde_json::from_slice(body).map_err(|_| AcmeError::malformed())?;
    let protected_b64 = envelope
        .get("protected")
        .and_then(Value::as_str)
        .ok_or_else(AcmeError::malformed)?;
    let protected_der = URL_SAFE_NO_PAD
        .decode(protected_b64)
        .map_err(|_| AcmeError::malformed())?;
    let protected = JwsHeader::from_bytes(&protected_der).map_err(|_| AcmeError::malformed())?;
    let expected_url = format!("{}{}", state.base_url, path);
    if protected.url() != Some(expected_url.as_str()) {
        return Err(AcmeError::malformed());
    }
    let (jwk, account_id) = match (protected.jwk(), protected.key_id()) {
        (Some(jwk), None) if allow_jwk => (jwk, None),
        (None, Some(kid)) if !allow_jwk => {
            let prefix = format!("{}/acme/account/", state.base_url);
            let account_id = kid
                .strip_prefix(&prefix)
                .ok_or_else(AcmeError::unauthorized)?
                .to_owned();
            let accounts = state.accounts.read().map_err(|_| AcmeError::server())?;
            let account = accounts
                .get(&account_id)
                .ok_or_else(AcmeError::unauthorized)?;
            (account.jwk.clone(), Some(account_id))
        }
        _ => return Err(AcmeError::unauthorized()),
    };
    let key_thumbprint = thumbprint(&jwk)?;
    let signer = verifier(protected.algorithm(), &jwk)?;
    let (payload, verified_header) = JwsContext::new()
        .deserialize_json(body, signer.as_ref())
        .map_err(|_| AcmeError::malformed())?;
    if verified_header.url() != Some(expected_url.as_str()) {
        return Err(AcmeError::malformed());
    }
    let nonce = verified_header.nonce().ok_or_else(AcmeError::bad_nonce)?;
    state.consume_nonce(&URL_SAFE_NO_PAD.encode(nonce))?;
    let payload = if payload.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&payload).map_err(|_| AcmeError::malformed())?
    };
    Ok(VerifiedRequest {
        principal: Principal {
            id: account_id.clone().unwrap_or(key_thumbprint),
        },
        payload,
        jwk,
        account_id,
    })
}

async fn handle_post(
    state: &Arc<AcmeState>,
    path: &str,
    body: &[u8],
) -> Result<Response, AcmeError> {
    let is_new_account = path == "/acme/new-account";
    let verified = verify_jws(state, path, body, is_new_account)?;
    match path {
        "/acme/new-account" => {
            if verified
                .payload
                .get("termsOfServiceAgreed")
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Err(AcmeError::unauthorized());
            }
            let contact: Vec<String> = verified
                .payload
                .get("contact")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let id = thumbprint(&verified.jwk)?;
            let mut accounts = state.accounts.write().map_err(|_| AcmeError::server())?;
            let existed = accounts.contains_key(&id);
            if !existed && accounts.len() >= MAX_ACME_RESOURCES {
                return Err(AcmeError::rate_limited());
            }
            accounts.entry(id.clone()).or_insert(Account {
                id: id.clone(),
                jwk: verified.jwk,
                thumbprint: id.clone(),
                contact: contact.clone(),
            });
            let url = format!("{}/acme/account/{id}", state.base_url);
            let response = json_response(
                if existed {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                json!({"status":"valid","contact":contact,"orders":format!("{}/acme/account/{id}/orders", state.base_url)}),
            );
            let mut response = response;
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&url).map_err(|_| AcmeError::server())?,
            );
            Ok(response)
        }
        "/acme/new-order" => create_order(state, verified),
        _ if path.starts_with("/acme/account/") => account_resource(state, path, verified),
        _ if path.starts_with("/acme/order/") => order_resource(state, path, verified),
        _ if path.starts_with("/acme/authz/") => authorization_resource(state, path, verified),
        _ if path.starts_with("/acme/challenge/") => {
            challenge_resource(state, path, verified).await
        }
        _ if path.starts_with("/acme/finalize/") => finalize_order(state, path, verified),
        _ if path.starts_with("/acme/certificate/") => certificate_resource(state, path, verified),
        _ => Err(AcmeError::not_found()),
    }
}

fn create_order(state: &AcmeState, verified: VerifiedRequest) -> Result<Response, AcmeError> {
    let identifiers = verified
        .payload
        .get("identifiers")
        .and_then(Value::as_array)
        .ok_or_else(AcmeError::malformed)?;
    if identifiers.is_empty() || identifiers.len() > MAX_ORDER_IDENTIFIERS {
        return Err(AcmeError::rejected());
    }
    let mut names = Vec::new();
    for identifier in identifiers {
        if identifier.get("type").and_then(Value::as_str) != Some("dns") {
            return Err(AcmeError::rejected());
        }
        let name = identifier
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(AcmeError::malformed)?
            .to_ascii_lowercase();
        if !valid_dns_name(&name) || names.contains(&name) {
            return Err(AcmeError::rejected());
        }
        let allowed = state
            .authority
            .policy
            .principal_dns_suffixes
            .get(&verified.principal.id)
            .unwrap_or(&state.authority.policy.allowed_dns_suffixes);
        if !allowed
            .iter()
            .any(|suffix| suffix_authorizes(&name, suffix))
        {
            return Err(AcmeError::rejected());
        }
        names.push(name);
    }
    let account_id = verified.account_id.ok_or_else(AcmeError::unauthorized)?;
    state
        .authority
        .check_rate_limit(&account_id)
        .map_err(|error| match error {
            EnrollmentError::RateLimited => AcmeError::rate_limited(),
            _ => AcmeError::server(),
        })?;
    if state.orders.read().map_err(|_| AcmeError::server())?.len() >= MAX_ACME_RESOURCES {
        return Err(AcmeError::rate_limited());
    }
    let order_id = state.next_id("order");
    let mut authz_ids = Vec::new();
    let expires = SystemTime::now()
        .checked_add(Duration::from_secs(7 * 24 * 60 * 60))
        .ok_or_else(AcmeError::server)?
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for name in &names {
        let authz_id = state.next_id("authz");
        let mut challenge_ids = Vec::new();
        for challenge_type in ["http-01", "dns-01"] {
            let mut random = [0u8; 32];
            getrandom::fill(&mut random).map_err(|_| AcmeError::server())?;
            let challenge_id = state.next_id("challenge");
            let challenge = Challenge {
                id: challenge_id.clone(),
                authorization_id: authz_id.clone(),
                account_id: account_id.clone(),
                identifier: name.clone(),
                challenge_type: challenge_type.to_owned(),
                token: URL_SAFE_NO_PAD.encode(random),
                status: "pending".to_owned(),
            };
            state
                .challenges
                .write()
                .map_err(|_| AcmeError::server())?
                .insert(challenge_id.clone(), challenge);
            challenge_ids.push(challenge_id);
        }
        state
            .authorizations
            .write()
            .map_err(|_| AcmeError::server())?
            .insert(
                authz_id.clone(),
                Authorization {
                    order_id: order_id.clone(),
                    account_id: account_id.clone(),
                    identifier: name.clone(),
                    status: "pending".to_owned(),
                    expires,
                    challenge_ids,
                },
            );
        authz_ids.push(authz_id);
    }
    let order = Order {
        id: order_id.clone(),
        account_id,
        identifiers: names,
        authorization_ids: authz_ids,
        status: "pending".to_owned(),
        certificate_chain: None,
        expires,
    };
    state
        .orders
        .write()
        .map_err(|_| AcmeError::server())?
        .insert(order_id.clone(), order.clone());
    let response = json_response(StatusCode::CREATED, order_json(state, &order));
    let url = format!("{}/acme/order/{order_id}", state.base_url);
    let mut response = response;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&url).map_err(|_| AcmeError::server())?,
    );
    Ok(response)
}

fn account_resource(
    state: &AcmeState,
    path: &str,
    verified: VerifiedRequest,
) -> Result<Response, AcmeError> {
    let id = path
        .trim_start_matches("/acme/account/")
        .split('/')
        .next()
        .unwrap_or_default();
    if verified.account_id.as_deref() != Some(id) {
        return Err(AcmeError::unauthorized());
    }
    let (account_id, contact) = {
        let accounts = state.accounts.read().map_err(|_| AcmeError::server())?;
        let account = accounts.get(id).ok_or_else(AcmeError::not_found)?;
        (account.id.clone(), account.contact.clone())
    };
    if path.ends_with("/orders") {
        let orders = state.orders.read().map_err(|_| AcmeError::server())?;
        let urls: Vec<String> = orders
            .values()
            .filter(|order| order.account_id == account_id)
            .map(|order| format!("{}/acme/order/{}", state.base_url, order.id))
            .collect();
        return Ok(json_response(StatusCode::OK, json!({"orders":urls})));
    }
    Ok(json_response(
        StatusCode::OK,
        json!({"status":"valid","contact":contact,"orders":format!("{}/acme/account/{}/orders", state.base_url, account_id)}),
    ))
}

fn order_json(state: &AcmeState, order: &Order) -> Value {
    let identifiers: Vec<Value> = order
        .identifiers
        .iter()
        .map(|name| json!({"type":"dns","value":name}))
        .collect();
    let authorizations: Vec<String> = order
        .authorization_ids
        .iter()
        .map(|id| format!("{}/acme/authz/{id}", state.base_url))
        .collect();
    let mut value = json!({"status":order.status,"expires":rfc3339(order.expires),"identifiers":identifiers,"authorizations":authorizations,"finalize":format!("{}/acme/finalize/{}", state.base_url, order.id)});
    if order.status == "valid" {
        value["certificate"] = json!(format!("{}/acme/certificate/{}", state.base_url, order.id));
    }
    value
}

fn order_resource(
    state: &AcmeState,
    path: &str,
    verified: VerifiedRequest,
) -> Result<Response, AcmeError> {
    let id = path.trim_start_matches("/acme/order/");
    let orders = state.orders.read().map_err(|_| AcmeError::server())?;
    let order = orders.get(id).ok_or_else(AcmeError::not_found)?;
    if verified.account_id.as_deref() != Some(order.account_id.as_str()) {
        return Err(AcmeError::unauthorized());
    }
    Ok(json_response(StatusCode::OK, order_json(state, order)))
}

fn authorization_json(state: &AcmeState, authz: &Authorization) -> Result<Value, AcmeError> {
    let challenges = state.challenges.read().map_err(|_| AcmeError::server())?;
    let values: Vec<Value> = authz.challenge_ids.iter().filter_map(|id| challenges.get(id)).map(|challenge| json!({"type":challenge.challenge_type,"url":format!("{}/acme/challenge/{}", state.base_url, challenge.id),"status":challenge.status,"token":challenge.token})).collect();
    Ok(
        json!({"identifier":{"type":"dns","value":authz.identifier},"status":authz.status,"expires":rfc3339(authz.expires),"challenges":values}),
    )
}

fn authorization_resource(
    state: &AcmeState,
    path: &str,
    verified: VerifiedRequest,
) -> Result<Response, AcmeError> {
    let id = path.trim_start_matches("/acme/authz/");
    let authorizations = state
        .authorizations
        .read()
        .map_err(|_| AcmeError::server())?;
    let authz = authorizations.get(id).ok_or_else(AcmeError::not_found)?;
    if verified.account_id.as_deref() != Some(authz.account_id.as_str()) {
        return Err(AcmeError::unauthorized());
    }
    Ok(json_response(
        StatusCode::OK,
        authorization_json(state, authz)?,
    ))
}

async fn challenge_resource(
    state: &AcmeState,
    path: &str,
    verified: VerifiedRequest,
) -> Result<Response, AcmeError> {
    let id = path.trim_start_matches("/acme/challenge/");
    let challenge = state
        .challenges
        .read()
        .map_err(|_| AcmeError::server())?
        .get(id)
        .cloned()
        .ok_or_else(AcmeError::not_found)?;
    if verified.account_id.as_deref() != Some(challenge.account_id.as_str()) {
        return Err(AcmeError::unauthorized());
    }
    if challenge.status == "valid" {
        return Ok(json_response(
            StatusCode::OK,
            challenge_json(state, &challenge),
        ));
    }
    let thumbprint = {
        let accounts = state.accounts.read().map_err(|_| AcmeError::server())?;
        accounts
            .get(&challenge.account_id)
            .ok_or_else(AcmeError::unauthorized)?
            .thumbprint
            .clone()
    };
    let key_authorization = format!("{}.{}", challenge.token, thumbprint);
    let dns_txt = if challenge.challenge_type == "dns-01" {
        Some(URL_SAFE_NO_PAD.encode(Sha256::digest(key_authorization.as_bytes())))
    } else {
        None
    };
    let valid = state
        .validator
        .validate(
            &challenge.challenge_type,
            &challenge.identifier,
            &challenge.token,
            &key_authorization,
            dns_txt.as_deref(),
        )
        .await;
    let status = if valid { "valid" } else { "invalid" };
    let mut updated = challenge.clone();
    updated.status = status.to_owned();
    state
        .challenges
        .write()
        .map_err(|_| AcmeError::server())?
        .insert(id.to_owned(), updated.clone());
    let authz_id = challenge.authorization_id.clone();
    {
        let challenges = state.challenges.read().map_err(|_| AcmeError::server())?;
        let mut authorizations = state
            .authorizations
            .write()
            .map_err(|_| AcmeError::server())?;
        if let Some(authz) = authorizations.get_mut(&authz_id) {
            if !valid {
                authz.status = "invalid".to_owned();
            } else if authz
                .challenge_ids
                .iter()
                .filter_map(|cid| challenges.get(cid))
                .any(|item| item.status == "valid")
            {
                authz.status = "valid".to_owned();
            }
        }
    }
    let authz_order_id = state
        .authorizations
        .read()
        .map_err(|_| AcmeError::server())?
        .get(&authz_id)
        .map(|a| a.order_id.clone())
        .ok_or_else(AcmeError::server)?;
    let all_authzs_valid = {
        let orders = state.orders.read().map_err(|_| AcmeError::server())?;
        let order = orders.get(&authz_order_id).ok_or_else(AcmeError::server)?;
        let authzs = state
            .authorizations
            .read()
            .map_err(|_| AcmeError::server())?;
        order.authorization_ids.iter().all(|authz_id| {
            authzs
                .get(authz_id)
                .is_some_and(|authz| authz.status == "valid")
        })
    };
    let any_authz_invalid = {
        let orders = state.orders.read().map_err(|_| AcmeError::server())?;
        let order = orders.get(&authz_order_id).ok_or_else(AcmeError::server)?;
        let authzs = state
            .authorizations
            .read()
            .map_err(|_| AcmeError::server())?;
        order.authorization_ids.iter().any(|authz_id| {
            authzs
                .get(authz_id)
                .is_some_and(|authz| authz.status == "invalid")
        })
    };
    if all_authzs_valid || any_authz_invalid {
        if let Some(order) = state
            .orders
            .write()
            .map_err(|_| AcmeError::server())?
            .get_mut(&authz_order_id)
        {
            order.status = if all_authzs_valid { "ready" } else { "invalid" }.to_owned();
        }
    }
    Ok(json_response(
        StatusCode::OK,
        challenge_json(state, &updated),
    ))
}

fn challenge_json(state: &AcmeState, challenge: &Challenge) -> Value {
    json!({"type":challenge.challenge_type,"url":format!("{}/acme/challenge/{}", state.base_url, challenge.id),"status":challenge.status,"token":challenge.token})
}

fn finalize_order(
    state: &AcmeState,
    path: &str,
    verified: VerifiedRequest,
) -> Result<Response, AcmeError> {
    let id = path.trim_start_matches("/acme/finalize/");
    let mut order = state
        .orders
        .read()
        .map_err(|_| AcmeError::server())?
        .get(id)
        .cloned()
        .ok_or_else(AcmeError::not_found)?;
    if verified.account_id.as_deref() != Some(order.account_id.as_str()) {
        return Err(AcmeError::unauthorized());
    }
    if order.status != "ready"
        || SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            >= order.expires
    {
        order.status = "invalid".to_owned();
        state
            .orders
            .write()
            .map_err(|_| AcmeError::server())?
            .insert(id.to_owned(), order);
        return Err(AcmeError::rejected());
    }
    let csr_b64 = verified
        .payload
        .get("csr")
        .and_then(Value::as_str)
        .ok_or_else(AcmeError::malformed)?;
    let csr_der = URL_SAFE_NO_PAD
        .decode(csr_b64)
        .map_err(|_| AcmeError::malformed())?;
    let csr = CertReq::from_der(&csr_der).map_err(|_| AcmeError::rejected())?;
    let mut names = requested_dns_names(&csr).map_err(|_| AcmeError::rejected())?;
    names.sort();
    let mut expected = order.identifiers.clone();
    expected.sort();
    if names != expected {
        return Err(AcmeError::rejected());
    }
    order.status = "processing".to_owned();
    state
        .orders
        .write()
        .map_err(|_| AcmeError::server())?
        .insert(id.to_owned(), order.clone());
    let principal = Principal {
        id: order.account_id.clone(),
    };
    let certificate = match state
        .authority
        .enroll_csr(&principal, Protocol::Acme, &csr_der)
    {
        Ok(certificate) => certificate,
        Err(error) => {
            order.status = if matches!(error, EnrollmentError::RateLimited) {
                "ready"
            } else {
                "invalid"
            }
            .to_owned();
            state
                .orders
                .write()
                .map_err(|_| AcmeError::server())?
                .insert(id.to_owned(), order);
            return Err(match error {
                EnrollmentError::RateLimited => AcmeError::rate_limited(),
                EnrollmentError::StateUnavailable
                | EnrollmentError::Issuance(_)
                | EnrollmentError::Signing(_)
                | EnrollmentError::ExternalSigning(_) => AcmeError::server(),
                _ => AcmeError::rejected(),
            });
        }
    };
    let mut chain = certificate
        .to_pem(LineEnding::LF)
        .map_err(|_| AcmeError::server())?;
    chain.push_str(
        &state
            .authority
            .issuer_certificate()
            .to_pem(LineEnding::LF)
            .map_err(|_| AcmeError::server())?,
    );
    order.status = "valid".to_owned();
    order.certificate_chain = Some(chain);
    state
        .orders
        .write()
        .map_err(|_| AcmeError::server())?
        .insert(id.to_owned(), order.clone());
    Ok(json_response(StatusCode::OK, order_json(state, &order)))
}

fn certificate_resource(
    state: &AcmeState,
    path: &str,
    verified: VerifiedRequest,
) -> Result<Response, AcmeError> {
    let id = path.trim_start_matches("/acme/certificate/");
    let orders = state.orders.read().map_err(|_| AcmeError::server())?;
    let order = orders.get(id).ok_or_else(AcmeError::not_found)?;
    if verified.account_id.as_deref() != Some(order.account_id.as_str()) {
        return Err(AcmeError::unauthorized());
    }
    if order.status != "valid" {
        return Err(AcmeError::rejected());
    }
    let chain = order
        .certificate_chain
        .as_ref()
        .ok_or_else(AcmeError::server)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pem-certificate-chain")],
        chain.clone(),
    )
        .into_response())
}

fn rfc3339(unix_seconds: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_seconds as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use der::{Encode, asn1::Ia5String};
    use josekit::jwk::alg::ec::EcCurve;
    use josekit::jws::JwsHeaderSet;
    use ml_dsa::{Generate, Keypair, MlDsa65, Signature as MlDsaSignature, SigningKey};
    use std::str::FromStr;
    use tower::ServiceExt;
    use x509_cert::{
        builder::{Builder, CertificateBuilder, profile::cabf},
        ext::pkix::{SubjectAltName, name::GeneralName},
        name::Name,
        request::RequestBuilder,
        serial_number::SerialNumber,
        spki::SubjectPublicKeyInfoOwned,
        time::Validity,
    };

    struct AlwaysValid;
    #[async_trait]
    impl AcmeChallengeValidator for AlwaysValid {
        async fn validate(
            &self,
            _kind: &str,
            _identifier: &str,
            _token: &str,
            _key_authorization: &str,
            _dns_txt_value: Option<&str>,
        ) -> bool {
            true
        }
    }

    fn fixture() -> (Arc<EnrollmentAuthority>, Vec<u8>) {
        let ca_key = SigningKey::<MlDsa65>::generate();
        let ca_name = Name::from_str("CN=NexusQ ACME Test Root,O=NexusQ,C=US").unwrap();
        let profile = cabf::Root::new(false, ca_name).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_key(&ca_key.verifying_key()).unwrap();
        let builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60)).unwrap(),
            spki,
        )
        .unwrap();
        let ca_cert = builder
            .build::<SigningKey<MlDsa65>, MlDsaSignature<MlDsa65>>(&ca_key)
            .unwrap();
        let policy = crate::EnrollmentPolicy::new(vec!["example.com".to_owned()]).unwrap();
        let authority = Arc::new(EnrollmentAuthority::new(ca_cert, ca_key, policy, 100).unwrap());
        let csr_key = SigningKey::<MlDsa65>::generate();
        let subject = Name::from_str("CN=service.example.com").unwrap();
        let mut request = RequestBuilder::new(subject).unwrap();
        request
            .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
                Ia5String::new("service.example.com").unwrap(),
            )]))
            .unwrap();
        let csr = request
            .build::<SigningKey<MlDsa65>, MlDsaSignature<MlDsa65>>(&csr_key)
            .unwrap();
        (authority, csr.to_der().unwrap())
    }

    fn sign_request(
        payload: &[u8],
        url: &str,
        nonce: &str,
        private_jwk: &Jwk,
        jwk: Option<Jwk>,
        kid: Option<&str>,
    ) -> String {
        let signer = ES256.signer_from_jwk(private_jwk).unwrap();
        let mut header = JwsHeaderSet::new();
        header.set_algorithm("ES256", true);
        header.set_url(url, true);
        header.set_nonce(URL_SAFE_NO_PAD.decode(nonce).unwrap(), true);
        if let Some(jwk) = jwk {
            header.set_jwk(jwk, true);
        }
        if let Some(kid) = kid {
            header.set_key_id(kid, true);
        }
        JwsContext::new()
            .serialize_flattened_json(payload, &header, &signer)
            .unwrap()
    }

    async fn post(app: &Router, path: &str, body: String) -> Response {
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/jose+json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn nonce(response: &Response) -> String {
        response
            .headers()
            .get("Replay-Nonce")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn acme_es256_account_order_challenge_finalize_and_certificate_flow() {
        use http_body_util::BodyExt;
        let (authority, csr) = fixture();
        let base = "https://pki.example.com";
        let app = authority.clone().acme_router(base, Arc::new(AlwaysValid));
        let key_pair = Jwk::generate_ec_key(EcCurve::P256).unwrap();
        let public_jwk = key_pair.to_public_key().unwrap();

        let nonce_response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::HEAD)
                    .uri("/acme/new-nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(nonce_response.status(), StatusCode::OK);
        let account_nonce = nonce(&nonce_response);
        let account_payload =
            json!({"termsOfServiceAgreed":true,"contact":["mailto:admin@example.com"]}).to_string();
        let account_jws = sign_request(
            account_payload.as_bytes(),
            &format!("{base}/acme/new-account"),
            &account_nonce,
            &key_pair,
            Some(public_jwk.clone()),
            None,
        );
        let account_response = post(&app, "/acme/new-account", account_jws.clone()).await;
        assert_eq!(account_response.status(), StatusCode::CREATED);
        let account_url = account_response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();
        let replay = post(&app, "/acme/new-account", account_jws).await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        let order_nonce = nonce(&account_response);

        let order_payload =
            json!({"identifiers":[{"type":"dns","value":"service.example.com"}]}).to_string();
        let signed = sign_request(
            order_payload.as_bytes(),
            &format!("{base}/acme/new-order"),
            &order_nonce,
            &key_pair,
            None,
            Some(&account_url),
        );
        let order_response = post(&app, "/acme/new-order", signed).await;
        assert_eq!(order_response.status(), StatusCode::CREATED);
        let order_nonce = nonce(&order_response);
        let order_body: Value = serde_json::from_slice(
            &order_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        let authz_url = order_body["authorizations"][0].as_str().unwrap().to_owned();
        let authz_path = authz_url.strip_prefix(base).unwrap();
        let signed = sign_request(
            b"",
            &authz_url,
            &order_nonce,
            &key_pair,
            None,
            Some(&account_url),
        );
        let authz_response = post(&app, authz_path, signed).await;
        assert_eq!(authz_response.status(), StatusCode::OK);
        let challenge_nonce = nonce(&authz_response);
        let authz_body: Value = serde_json::from_slice(
            &authz_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        let challenge_url = authz_body["challenges"][0]["url"]
            .as_str()
            .unwrap()
            .to_owned();
        let challenge_path = challenge_url.strip_prefix(base).unwrap();
        let signed = sign_request(
            b"{}",
            &challenge_url,
            &challenge_nonce,
            &key_pair,
            None,
            Some(&account_url),
        );
        let challenge_response = post(&app, challenge_path, signed).await;
        assert_eq!(challenge_response.status(), StatusCode::OK);
        let finalize_nonce = nonce(&challenge_response);

        let finalize_url = order_body["finalize"].as_str().unwrap().to_owned();
        let finalize_path = finalize_url.strip_prefix(base).unwrap();
        let finalize_payload = json!({"csr":URL_SAFE_NO_PAD.encode(csr)}).to_string();
        let signed = sign_request(
            finalize_payload.as_bytes(),
            &finalize_url,
            &finalize_nonce,
            &key_pair,
            None,
            Some(&account_url),
        );
        let finalize_response = post(&app, finalize_path, signed).await;
        assert_eq!(finalize_response.status(), StatusCode::OK);
        let certificate_nonce = nonce(&finalize_response);
        let finalized: Value = serde_json::from_slice(
            &finalize_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        assert_eq!(finalized["status"], "valid");
        let certificate_url = finalized["certificate"].as_str().unwrap().to_owned();
        let certificate_path = certificate_url.strip_prefix(base).unwrap();
        let signed = sign_request(
            b"",
            &certificate_url,
            &certificate_nonce,
            &key_pair,
            None,
            Some(&account_url),
        );
        let certificate_response = post(&app, certificate_path, signed).await;
        assert_eq!(certificate_response.status(), StatusCode::OK);
        assert_eq!(
            certificate_response.headers()[header::CONTENT_TYPE],
            "application/pem-certificate-chain"
        );
        let pem_chain = certificate_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert!(
            std::str::from_utf8(&pem_chain)
                .unwrap()
                .matches("BEGIN CERTIFICATE")
                .count()
                >= 2
        );
        assert!(
            authority
                .audit_events()
                .iter()
                .any(|event| event.protocol == "acme" && event.outcome == "issued")
        );
    }
}

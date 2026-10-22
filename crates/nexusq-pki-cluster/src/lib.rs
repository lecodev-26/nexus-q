//! Tenant-routed CA/OCSP runtime for NexusQ HA deployments.
//!
//! Mount one independently configured `EnrollmentAuthority` and `OcspService` per tenant. Each
//! service should use a tenant-specific `HaCoordinator`/journal and a consensus-issued lease. CA
//! enrollment requires a per-tenant bearer token; OCSP and CRL remain public PKI endpoints but are
//! rate-limited independently by tenant. This runtime never accepts CA private-key material over
//! HTTP and never logs bearer tokens or CSR contents.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::Encode;
use nexusq_admin::{AdminError, AuditAction, AuditLog, AuditOutcome, Permission, RbacStore};
use nexusq_enrollment::{EnrollmentAuthority, Error as EnrollmentError, Principal, Protocol};
use nexusq_ha::{
    DurableTenantJournal, HaError, JournalRecord, LeadershipLease, RecoveryObjectives, ReplicaPeer,
    TenantCatalog, TenantDescriptor, TenantId, TenantRateLimiter,
};
use nexusq_ocsp::{Error as OcspError, OcspService};
use reqwest::{Certificate as TlsRootCertificate, Identity, Url, blocking::Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Clone)]
struct TenantRuntime {
    authority: Arc<EnrollmentAuthority>,
    ocsp: Arc<OcspService>,
    bearer_token_sha256: [u8; 32],
}

/// Tenant runtime registry and HTTP router. The catalog should be opened from durable storage.
pub struct PkiTenantRegistry {
    catalog: Arc<TenantCatalog>,
    tenants: RwLock<HashMap<TenantId, TenantRuntime>>,
    limiter: TenantRateLimiter,
    objectives: RecoveryObjectives,
    audit: RwLock<Option<Arc<AuditLog>>>,
}

/// Errors while configuring the tenant runtime.
#[derive(Debug, Error)]
pub enum ClusterError {
    /// Tenant catalog or HA state failed.
    #[error("HA configuration failed: {0}")]
    Ha(#[from] HaError),
    /// The configured CA certificate differs across tenant services or catalog metadata.
    #[error("tenant CA certificate fingerprint mismatch")]
    CaFingerprintMismatch,
    /// Token must be at least 32 bytes.
    #[error("tenant bearer token must contain at least 32 bytes")]
    WeakToken,
    /// Tenant runtime is already mounted.
    #[error("tenant runtime already mounted")]
    AlreadyMounted,
    /// Recovery objectives exceed required bounds.
    #[error("invalid recovery objectives")]
    InvalidRecoveryObjectives,
    /// CA and OCSP services are not attached to the same tenant-scoped HA coordinator.
    #[error("CA and OCSP services must share the same tenant journal and coordinator")]
    HaTenantMismatch,
    /// Leadership lease could not be renewed consistently across tenant services.
    #[error("tenant lease renewal failed")]
    LeaseRenewalFailed,
}

#[derive(Deserialize)]
struct EnrollRequest {
    principal_id: String,
    csr_der_base64: String,
}
#[derive(Serialize)]
struct EnrollResponse {
    tenant: String,
    serial_number: String,
    certificate_der_base64: String,
}
#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

impl PkiTenantRegistry {
    /// Create a registry around a persistent tenant catalog and the required RPO/RTO objectives.
    pub fn new(
        catalog: Arc<TenantCatalog>,
        objectives: RecoveryObjectives,
    ) -> Result<Self, ClusterError> {
        objectives
            .validate()
            .map_err(|_| ClusterError::InvalidRecoveryObjectives)?;
        Ok(Self {
            catalog,
            tenants: RwLock::new(HashMap::new()),
            limiter: TenantRateLimiter::new(std::time::Duration::from_secs(60))
                .map_err(ClusterError::Ha)?,
            objectives,
            audit: RwLock::new(None),
        })
    }

    /// Mount services for one tenant. Both services must use the same CA certificate, and the
    /// supplied descriptor fingerprint must match that certificate's DER SHA-256 digest.
    pub fn mount_tenant(
        &self,
        descriptor: TenantDescriptor,
        authority: Arc<EnrollmentAuthority>,
        ocsp: Arc<OcspService>,
        bearer_token: &str,
    ) -> Result<(), ClusterError> {
        if bearer_token.len() < 32 {
            return Err(ClusterError::WeakToken);
        }
        if authority.ha_tenant_id() != Some(&descriptor.id)
            || ocsp.ha_tenant_id() != Some(&descriptor.id)
            || !matches!((authority.ha_coordinator(), ocsp.ha_coordinator()), (Some(ca), Some(status)) if Arc::ptr_eq(ca, status))
        {
            return Err(ClusterError::HaTenantMismatch);
        }
        let ca_der = authority
            .issuer_certificate()
            .to_der()
            .map_err(|_| ClusterError::CaFingerprintMismatch)?;
        let ocsp_der = ocsp
            .issuer_certificate()
            .to_der()
            .map_err(|_| ClusterError::CaFingerprintMismatch)?;
        let fingerprint: [u8; 32] = Sha256::digest(&ca_der).into();
        if ca_der != ocsp_der || fingerprint != descriptor.ca_certificate_sha256 {
            return Err(ClusterError::CaFingerprintMismatch);
        }
        match self.catalog.get(&descriptor.id) {
            Ok(existing) if existing != descriptor => {
                return Err(ClusterError::CaFingerprintMismatch);
            }
            Ok(_) => {}
            Err(HaError::TenantNotFound) => self.catalog.register(descriptor.clone())?,
            Err(error) => return Err(ClusterError::Ha(error)),
        }
        let mut tenants = self
            .tenants
            .write()
            .map_err(|_| ClusterError::Ha(HaError::StateUnavailable))?;
        if tenants.contains_key(&descriptor.id) {
            return Err(ClusterError::AlreadyMounted);
        }
        let bearer_token_sha256 = Sha256::digest(bearer_token.as_bytes()).into();
        tenants.insert(
            descriptor.id,
            TenantRuntime {
                authority,
                ocsp,
                bearer_token_sha256,
            },
        );
        Ok(())
    }

    /// Renew a tenant's lease in both CA and OCSP services after the consensus provider grants a newer fencing epoch.
    pub fn update_tenant_lease(
        &self,
        tenant: &TenantId,
        lease: LeadershipLease,
    ) -> Result<(), ClusterError> {
        let tenants = self
            .tenants
            .read()
            .map_err(|_| ClusterError::Ha(HaError::StateUnavailable))?;
        let runtime = tenants
            .get(tenant)
            .ok_or(ClusterError::Ha(HaError::TenantNotFound))?;
        runtime
            .authority
            .update_leadership_lease(lease.clone())
            .map_err(|_| ClusterError::LeaseRenewalFailed)?;
        runtime
            .ocsp
            .update_leadership_lease(lease)
            .map_err(|_| ClusterError::LeaseRenewalFailed)?;
        Ok(())
    }

    /// Build tenant-aware routes: authenticated enrollment, public OCSP, and public CRL.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/tenants/{tenant}/enroll", post(enroll_handler))
            .route("/tenants/{tenant}/ocsp", post(ocsp_handler))
            .route("/tenants/{tenant}/crl", get(crl_handler))
            .route("/tenants/{tenant}/health", get(tenant_health_handler))
            .layer(DefaultBodyLimit::max(1024 * 1024))
            .with_state(self)
    }

    /// Recovery objectives applied by this cluster runtime.
    pub fn recovery_objectives(&self) -> RecoveryObjectives {
        self.objectives
    }

    /// Build the public tenant router plus RBAC-protected administrative routes.
    pub fn router_with_admin(
        self: Arc<Self>,
        rbac: Arc<RbacStore>,
        audit: Arc<AuditLog>,
    ) -> Router {
        if let Ok(mut slot) = self.audit.write() {
            *slot = Some(audit.clone());
        }
        let public = self.clone().router();
        let admin = Router::new()
            .route("/admin/tenants/{tenant}", get(admin_tenant_status_handler))
            .route(
                "/admin/tenants/{tenant}/issuance",
                post(admin_set_issuance_handler),
            )
            .with_state(AdminApiState {
                registry: self,
                rbac,
                audit,
            });
        public.merge(admin)
    }

    fn audit_event(
        &self,
        actor: &str,
        action: AuditAction,
        tenant: Option<&TenantId>,
        outcome: AuditOutcome,
        resource: Option<&str>,
    ) -> Result<(), StatusCode> {
        let slot = self
            .audit
            .read()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if let Some(audit) = slot.as_ref() {
            audit
                .append(actor, action, tenant, outcome, resource)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        Ok(())
    }

    fn runtime(
        &self,
        raw_tenant: &str,
    ) -> Result<(TenantId, TenantDescriptor, TenantRuntime), StatusCode> {
        let tenant = TenantId::new(raw_tenant).map_err(|_| StatusCode::NOT_FOUND)?;
        let descriptor = self
            .catalog
            .get(&tenant)
            .map_err(|_| StatusCode::NOT_FOUND)?;
        let runtime = self
            .tenants
            .read()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .get(&tenant)
            .cloned()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        Ok((tenant, descriptor, runtime))
    }

    fn allow_request(
        &self,
        tenant: &TenantId,
        descriptor: &TenantDescriptor,
    ) -> Result<(), StatusCode> {
        self.limiter
            .allow(tenant, descriptor.requests_per_minute, SystemTime::now())
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .then_some(())
            .ok_or(StatusCode::TOO_MANY_REQUESTS)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReplicaPrepareRequest {
    leader_id: String,
    record: JournalRecord,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReplicaDecisionRequest {
    leader_id: String,
    sequence: u64,
    hash: [u8; 32],
    term: u64,
}

/// Authenticated replica receiver. Mount this router only behind an internal TLS/mTLS listener.
pub struct ReplicaNode {
    node_id: String,
    journal: Arc<DurableTenantJournal>,
    allowed_leaders: HashSet<String>,
    bearer_token_sha256: [u8; 32],
}
impl ReplicaNode {
    /// Configure a replica receiver with an allowlist of leader identities and a node-specific token.
    pub fn new(
        node_id: impl Into<String>,
        journal: Arc<DurableTenantJournal>,
        allowed_leaders: impl IntoIterator<Item = String>,
        bearer_token: &str,
    ) -> Result<Self, HaError> {
        let node_id = node_id.into();
        let allowed_leaders = allowed_leaders.into_iter().collect::<HashSet<_>>();
        if node_id.is_empty()
            || !node_id.is_ascii()
            || node_id.chars().any(char::is_control)
            || allowed_leaders.is_empty()
            || allowed_leaders
                .iter()
                .any(|id| id.is_empty() || !id.is_ascii() || id.chars().any(char::is_control))
            || bearer_token.len() < 32
        {
            return Err(HaError::InvalidPeerConfig);
        }
        Ok(Self {
            node_id,
            journal,
            allowed_leaders,
            bearer_token_sha256: Sha256::digest(bearer_token.as_bytes()).into(),
        })
    }
    /// Stable receiver identity.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
    /// Tenant namespace persisted by this receiver.
    pub fn tenant(&self) -> &TenantId {
        self.journal.tenant()
    }
    /// Internal replication routes. Expose only through private network controls and mTLS verification.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/internal/replica/prepare", post(replica_prepare_handler))
            .route("/internal/replica/commit", post(replica_commit_handler))
            .route("/internal/replica/abort", post(replica_abort_handler))
            .layer(DefaultBodyLimit::max(64 * 1024 * 1024 + 8192))
            .with_state(self)
    }
    fn authorize(&self, headers: &HeaderMap, leader_id: &str) -> bool {
        if !self.allowed_leaders.contains(leader_id) {
            return false;
        }
        let Some(value) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        let Some(token) = value.strip_prefix("Bearer ") else {
            return false;
        };
        bool::from(
            Sha256::digest(token.as_bytes())
                .as_slice()
                .ct_eq(&self.bearer_token_sha256),
        )
    }
}

/// HTTPS peer client implementing the HA coordinator's synchronous replication contract.
/// The client validates the peer TLS certificate, trusts the supplied private CA, and presents
/// a client certificate. The server should additionally enforce mTLS at the reverse proxy.
pub struct HttpReplicaPeer {
    local_node_id: String,
    peer_node_id: String,
    base_url: Url,
    bearer_token: zeroize::Zeroizing<String>,
    client: Client,
}
impl HttpReplicaPeer {
    /// Build a peer connection. `identity_pem` must contain the client certificate chain and
    /// private key; `root_ca_pem` must be the CA that validates the peer server certificate.
    pub fn new(
        local_node_id: impl Into<String>,
        peer_node_id: impl Into<String>,
        base_url: &str,
        bearer_token: String,
        root_ca_pem: &[u8],
        identity_pem: &[u8],
    ) -> Result<Self, HaError> {
        let local_node_id = local_node_id.into();
        let peer_node_id = peer_node_id.into();
        let mut url = Url::parse(base_url).map_err(|_| HaError::InvalidPeerConfig)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || local_node_id.is_empty()
            || peer_node_id.is_empty()
            || local_node_id == peer_node_id
            || bearer_token.len() < 32
        {
            return Err(HaError::InvalidPeerConfig);
        }
        let normalized_path = format!("{}/", url.path().trim_end_matches('/'));
        url.set_path(&normalized_path);
        let root =
            TlsRootCertificate::from_pem(root_ca_pem).map_err(|_| HaError::InvalidPeerConfig)?;
        let identity = Identity::from_pem(identity_pem).map_err(|_| HaError::InvalidPeerConfig)?;
        let client = Client::builder()
            .add_root_certificate(root)
            .identity(identity)
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|_| HaError::InvalidPeerConfig)?;
        Ok(Self {
            local_node_id,
            peer_node_id,
            base_url: url,
            bearer_token: zeroize::Zeroizing::new(bearer_token),
            client,
        })
    }
    fn send<T: Serialize>(&self, endpoint: &str, body: &T) -> Result<(), HaError> {
        let url = self
            .base_url
            .join(endpoint)
            .map_err(|_| HaError::InvalidPeerConfig)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(self.bearer_token.as_str())
            .json(body)
            .send()
            .map_err(|_| HaError::StorageUnavailable)?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err(HaError::StorageUnavailable);
        }
        Ok(())
    }
}
impl ReplicaPeer for HttpReplicaPeer {
    fn node_id(&self) -> &str {
        &self.peer_node_id
    }
    fn prepare(&self, record: &JournalRecord) -> Result<(), HaError> {
        self.send(
            "internal/replica/prepare",
            &ReplicaPrepareRequest {
                leader_id: self.local_node_id.clone(),
                record: record.clone(),
            },
        )
    }
    fn commit(&self, sequence: u64, hash: [u8; 32], term: u64) -> Result<(), HaError> {
        self.send(
            "internal/replica/commit",
            &ReplicaDecisionRequest {
                leader_id: self.local_node_id.clone(),
                sequence,
                hash,
                term,
            },
        )
    }
    fn abort(&self, sequence: u64, hash: [u8; 32], term: u64) -> Result<(), HaError> {
        self.send(
            "internal/replica/abort",
            &ReplicaDecisionRequest {
                leader_id: self.local_node_id.clone(),
                sequence,
                hash,
                term,
            },
        )
    }
}

async fn replica_prepare_handler(
    State(node): State<Arc<ReplicaNode>>,
    headers: HeaderMap,
    Json(request): Json<ReplicaPrepareRequest>,
) -> Response {
    if !node.authorize(&headers, &request.leader_id) {
        return error(StatusCode::UNAUTHORIZED, "replica authentication failed");
    }
    match node.journal.accept_replica_prepare(&request.record) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(HaError::HashMismatch | HaError::NotLeader | HaError::UnresolvedTransaction) => {
            error(StatusCode::CONFLICT, "replica prepare rejected")
        }
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "replica storage unavailable",
        ),
    }
}
async fn replica_commit_handler(
    State(node): State<Arc<ReplicaNode>>,
    headers: HeaderMap,
    Json(request): Json<ReplicaDecisionRequest>,
) -> Response {
    if !node.authorize(&headers, &request.leader_id) {
        return error(StatusCode::UNAUTHORIZED, "replica authentication failed");
    }
    match node
        .journal
        .accept_replica_commit(request.sequence, request.hash, request.term)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(HaError::HashMismatch | HaError::NotLeader | HaError::TransactionNotFound) => {
            error(StatusCode::CONFLICT, "replica commit rejected")
        }
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "replica storage unavailable",
        ),
    }
}
async fn replica_abort_handler(
    State(node): State<Arc<ReplicaNode>>,
    headers: HeaderMap,
    Json(request): Json<ReplicaDecisionRequest>,
) -> Response {
    if !node.authorize(&headers, &request.leader_id) {
        return error(StatusCode::UNAUTHORIZED, "replica authentication failed");
    }
    match node
        .journal
        .accept_replica_abort(request.sequence, request.hash, request.term)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(HaError::HashMismatch | HaError::NotLeader | HaError::TransactionNotFound) => {
            error(StatusCode::CONFLICT, "replica abort rejected")
        }
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "replica storage unavailable",
        ),
    }
}

#[derive(Clone)]
struct AdminApiState {
    registry: Arc<PkiTenantRegistry>,
    rbac: Arc<RbacStore>,
    audit: Arc<AuditLog>,
}
#[derive(Deserialize)]
struct SetIssuanceRequest {
    enabled: bool,
}
#[derive(Serialize)]
struct AdminTenantResponse {
    tenant: String,
    issuance_enabled: bool,
    requests_per_minute: u32,
}

async fn admin_tenant_status_handler(
    State(state): State<AdminApiState>,
    Path(raw_tenant): Path<String>,
    headers: HeaderMap,
) -> Response {
    let tenant = match TenantId::new(raw_tenant) {
        Ok(tenant) => tenant,
        Err(_) => return error(StatusCode::NOT_FOUND, "tenant unavailable"),
    };
    let principal = match authenticate_admin(&state, &headers, &tenant) {
        Ok(principal) => principal,
        Err(status) => return error(status, "administrative authorization denied"),
    };
    if !principal.allows(Permission::ReadHealth, Some(&tenant)) {
        let _ = state.audit.append(
            &principal.subject,
            AuditAction::AuthorizationDenied,
            Some(&tenant),
            AuditOutcome::Denied,
            Some("tenant-status"),
        );
        return error(StatusCode::FORBIDDEN, "administrative authorization denied");
    }
    let descriptor = match state.registry.catalog.get(&tenant) {
        Ok(descriptor) => descriptor,
        Err(_) => return error(StatusCode::NOT_FOUND, "tenant unavailable"),
    };
    if state
        .audit
        .append(
            &principal.subject,
            AuditAction::TenantStatusRead,
            Some(&tenant),
            AuditOutcome::Success,
            Some("tenant-status"),
        )
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    Json(AdminTenantResponse {
        tenant: tenant.as_str().to_owned(),
        issuance_enabled: descriptor.issuance_enabled,
        requests_per_minute: descriptor.requests_per_minute,
    })
    .into_response()
}

async fn admin_set_issuance_handler(
    State(state): State<AdminApiState>,
    Path(raw_tenant): Path<String>,
    headers: HeaderMap,
    Json(request): Json<SetIssuanceRequest>,
) -> Response {
    let tenant = match TenantId::new(raw_tenant) {
        Ok(tenant) => tenant,
        Err(_) => return error(StatusCode::NOT_FOUND, "tenant unavailable"),
    };
    let principal = match authenticate_admin(&state, &headers, &tenant) {
        Ok(principal) => principal,
        Err(status) => return error(status, "administrative authorization denied"),
    };
    if !principal.allows(Permission::ManageTenant, Some(&tenant)) {
        let _ = state.audit.append(
            &principal.subject,
            AuditAction::AuthorizationDenied,
            Some(&tenant),
            AuditOutcome::Denied,
            Some("issuance-policy"),
        );
        return error(StatusCode::FORBIDDEN, "administrative authorization denied");
    }
    let previous = match state.registry.catalog.get(&tenant) {
        Ok(descriptor) => descriptor.issuance_enabled,
        Err(_) => return error(StatusCode::NOT_FOUND, "tenant unavailable"),
    };
    let resource = if request.enabled {
        "issuance-enable"
    } else {
        "issuance-disable"
    };
    if state
        .audit
        .append(
            &principal.subject,
            AuditAction::TenantIssuanceChanged,
            Some(&tenant),
            AuditOutcome::Requested,
            Some(resource),
        )
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    if state
        .registry
        .catalog
        .set_issuance(&tenant, request.enabled)
        .is_err()
    {
        let _ = state.audit.append(
            &principal.subject,
            AuditAction::TenantIssuanceChanged,
            Some(&tenant),
            AuditOutcome::Failed,
            Some(resource),
        );
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant policy update failed",
        );
    }
    if state
        .audit
        .append(
            &principal.subject,
            AuditAction::TenantIssuanceChanged,
            Some(&tenant),
            AuditOutcome::Success,
            Some(resource),
        )
        .is_err()
    {
        let _ = state.registry.catalog.set_issuance(&tenant, previous);
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit unavailable; policy change rolled back",
        );
    }
    let descriptor = match state.registry.catalog.get(&tenant) {
        Ok(descriptor) => descriptor,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "tenant policy unavailable"),
    };
    Json(AdminTenantResponse {
        tenant: tenant.as_str().to_owned(),
        issuance_enabled: descriptor.issuance_enabled,
        requests_per_minute: descriptor.requests_per_minute,
    })
    .into_response()
}

fn authenticate_admin(
    state: &AdminApiState,
    headers: &HeaderMap,
    tenant: &TenantId,
) -> Result<nexusq_admin::AdminPrincipal, StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        if state
            .audit
            .append(
                "anonymous",
                AuditAction::AuthorizationDenied,
                Some(tenant),
                AuditOutcome::Denied,
                Some("admin-auth"),
            )
            .is_err()
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        return Err(StatusCode::UNAUTHORIZED);
    };
    match state.rbac.authenticate(token) {
        Ok(principal) => Ok(principal),
        Err(AdminError::AuthenticationDenied) => {
            if state
                .audit
                .append(
                    "anonymous",
                    AuditAction::AuthorizationDenied,
                    Some(tenant),
                    AuditOutcome::Denied,
                    Some("admin-auth"),
                )
                .is_err()
            {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            Err(StatusCode::UNAUTHORIZED)
        }
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn authorized(headers: &HeaderMap, expected: &[u8; 32]) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    if token.len() < 32 {
        return false;
    }
    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    bool::from(actual.ct_eq(expected))
}

async fn enroll_handler(
    State(registry): State<Arc<PkiTenantRegistry>>,
    Path(raw_tenant): Path<String>,
    headers: HeaderMap,
    Json(request): Json<EnrollRequest>,
) -> Response {
    let (tenant, descriptor, runtime) = match registry.runtime(&raw_tenant) {
        Ok(value) => value,
        Err(status) => return error(status, "tenant unavailable"),
    };
    if !authorized(&headers, &runtime.bearer_token_sha256) {
        if registry
            .audit_event(
                "anonymous",
                AuditAction::AuthorizationDenied,
                Some(&tenant),
                AuditOutcome::Denied,
                Some("enrollment-auth"),
            )
            .is_err()
        {
            return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
        }
        return error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    if !descriptor.issuance_enabled {
        return error(StatusCode::FORBIDDEN, "issuance disabled");
    }
    if let Err(status) = registry.allow_request(&tenant, &descriptor) {
        return error(status, "tenant rate limit exceeded");
    }
    if request.principal_id.is_empty()
        || request.principal_id.len() > 256
        || request.principal_id.chars().any(char::is_control)
    {
        return error(StatusCode::BAD_REQUEST, "invalid principal");
    }
    let csr = match STANDARD.decode(request.csr_der_base64.as_bytes()) {
        Ok(csr) if !csr.is_empty() && csr.len() <= 256 * 1024 => csr,
        _ => return error(StatusCode::BAD_REQUEST, "invalid CSR encoding"),
    };
    if registry
        .audit_event(
            &request.principal_id,
            AuditAction::CertificateIssued,
            Some(&tenant),
            AuditOutcome::Requested,
            Some("certificate-issuance"),
        )
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    let actor = request.principal_id.clone();
    let authority = runtime.authority.clone();
    let principal = Principal {
        id: request.principal_id,
    };
    let issued =
        tokio::task::spawn_blocking(move || authority.enroll_csr(&principal, Protocol::Est, &csr))
            .await;
    match issued {
        Ok(Ok(certificate)) => match certificate.to_der() {
            Ok(der) => {
                let serial = certificate.tbs_certificate().serial_number().to_string();
                if registry
                    .audit_event(
                        &actor,
                        AuditAction::CertificateIssued,
                        Some(&tenant),
                        AuditOutcome::Success,
                        Some(&serial),
                    )
                    .is_err()
                {
                    return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
                }
                Json(EnrollResponse {
                    tenant: tenant.as_str().to_owned(),
                    serial_number: serial,
                    certificate_der_base64: STANDARD.encode(der),
                })
                .into_response()
            }
            Err(_) => error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "certificate encoding failed",
            ),
        },
        Ok(Err(EnrollmentError::RateLimited)) => error(
            StatusCode::TOO_MANY_REQUESTS,
            "enrollment rate limit exceeded",
        ),
        Ok(Err(
            EnrollmentError::StateUnavailable
            | EnrollmentError::Ha(_)
            | EnrollmentError::Issuance(_)
            | EnrollmentError::Signing(_)
            | EnrollmentError::ExternalSigning(_),
        )) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "certificate issuance unavailable",
        ),
        Ok(Err(_)) => error(StatusCode::BAD_REQUEST, "certificate request rejected"),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "issuance worker unavailable",
        ),
    }
}

async fn ocsp_handler(
    State(registry): State<Arc<PkiTenantRegistry>>,
    Path(raw_tenant): Path<String>,
    body: Bytes,
) -> Response {
    let (tenant, descriptor, runtime) = match registry.runtime(&raw_tenant) {
        Ok(value) => value,
        Err(status) => return error(status, "tenant unavailable"),
    };
    if let Err(status) = registry.allow_request(&tenant, &descriptor) {
        return error(status, "tenant rate limit exceeded");
    }
    if registry
        .audit_event(
            "anonymous",
            AuditAction::OcspQuery,
            Some(&tenant),
            AuditOutcome::Requested,
            Some("ocsp-query"),
        )
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    match runtime.ocsp.respond(&body) {
        Ok(response) => {
            if registry
                .audit_event(
                    "anonymous",
                    AuditAction::OcspQuery,
                    Some(&tenant),
                    AuditOutcome::Success,
                    Some("ocsp-query"),
                )
                .is_err()
            {
                return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
            }
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/ocsp-response")],
                response,
            )
                .into_response()
        }
        Err(
            OcspError::Der(_)
            | OcspError::InvalidRequestSize
            | OcspError::UnsupportedHashAlgorithm
            | OcspError::IssuerMismatch
            | OcspError::UnsupportedRequestFeatures,
        ) => {
            if registry
                .audit_event(
                    "anonymous",
                    AuditAction::OcspQuery,
                    Some(&tenant),
                    AuditOutcome::Denied,
                    Some("ocsp-query"),
                )
                .is_err()
            {
                return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
            }
            error(StatusCode::BAD_REQUEST, "invalid OCSP request")
        }
        Err(_) => {
            let _ = registry.audit_event(
                "anonymous",
                AuditAction::OcspQuery,
                Some(&tenant),
                AuditOutcome::Failed,
                Some("ocsp-query"),
            );
            error(StatusCode::SERVICE_UNAVAILABLE, "OCSP service unavailable")
        }
    }
}

async fn crl_handler(
    State(registry): State<Arc<PkiTenantRegistry>>,
    Path(raw_tenant): Path<String>,
) -> Response {
    let (tenant, descriptor, runtime) = match registry.runtime(&raw_tenant) {
        Ok(value) => value,
        Err(status) => return error(status, "tenant unavailable"),
    };
    if let Err(status) = registry.allow_request(&tenant, &descriptor) {
        return error(status, "tenant rate limit exceeded");
    }
    if registry
        .audit_event(
            "anonymous",
            AuditAction::CrlRead,
            Some(&tenant),
            AuditOutcome::Requested,
            Some("crl-read"),
        )
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
    }
    match runtime.ocsp.current_crl() {
        Ok(crl) => {
            if registry
                .audit_event(
                    "anonymous",
                    AuditAction::CrlRead,
                    Some(&tenant),
                    AuditOutcome::Success,
                    Some("crl-read"),
                )
                .is_err()
            {
                return error(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable");
            }
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/pkix-crl")],
                crl,
            )
                .into_response()
        }
        Err(_) => {
            let _ = registry.audit_event(
                "anonymous",
                AuditAction::CrlRead,
                Some(&tenant),
                AuditOutcome::Failed,
                Some("crl-read"),
            );
            error(StatusCode::SERVICE_UNAVAILABLE, "CRL service unavailable")
        }
    }
}

async fn tenant_health_handler(
    State(registry): State<Arc<PkiTenantRegistry>>,
    Path(raw_tenant): Path<String>,
) -> Response {
    match registry.runtime(&raw_tenant) {
        Ok((tenant, descriptor, _)) => Json(serde_json::json!({"status":"ready", "tenant":tenant.as_str(), "issuance_enabled":descriptor.issuance_enabled})).into_response(),
        Err(status) => error(status, "tenant unavailable"),
    }
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorResponse { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use der::{Encode, asn1::Ia5String};
    use ml_dsa::{Generate, Keypair, MlDsa65, Signature, SigningKey};
    use nexusq_enrollment::EnrollmentPolicy;
    use std::{str::FromStr, time::UNIX_EPOCH};
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

    fn services(
        dir: &std::path::Path,
    ) -> (
        Arc<EnrollmentAuthority>,
        Arc<OcspService>,
        TenantDescriptor,
        String,
    ) {
        let key = SigningKey::<MlDsa65>::generate();
        let subject = Name::from_str("CN=NexusQ Cluster Test Root,O=NexusQ,C=US").unwrap();
        let profile = cabf::Root::new(false, subject).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_key(&key.verifying_key()).unwrap();
        let builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            Validity::from_now(std::time::Duration::from_secs(86400)).unwrap(),
            spki,
        )
        .unwrap();
        let cert = builder
            .build::<SigningKey<MlDsa65>, Signature<MlDsa65>>(&key)
            .unwrap();
        let policy = EnrollmentPolicy::new(vec!["example.com".to_owned()]).unwrap();
        let tenant_id = TenantId::new("alpha").unwrap();
        let journal =
            Arc::new(nexusq_ha::DurableTenantJournal::open(dir, tenant_id.clone()).unwrap());
        let coordinator =
            Arc::new(nexusq_ha::HaCoordinator::new("node-a", journal, vec![]).unwrap());
        let lease = nexusq_ha::LeadershipLease {
            leader_id: "node-a".into(),
            term: 1,
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 300,
            fencing_epoch: 1,
        };
        let authority = Arc::new(
            EnrollmentAuthority::new_ha(
                cert.clone(),
                Arc::new(key.clone()),
                policy,
                10,
                coordinator.clone(),
                lease.clone(),
            )
            .unwrap(),
        );
        let ocsp = Arc::new(
            OcspService::new_ha(
                cert.clone(),
                key,
                nexusq_ocsp::RevocationStore::new(),
                1,
                coordinator,
                lease,
            )
            .unwrap(),
        );
        let fingerprint: [u8; 32] = Sha256::digest(cert.to_der().unwrap()).into();
        let descriptor = TenantDescriptor {
            id: tenant_id,
            ca_certificate_sha256: fingerprint,
            requests_per_minute: 20,
            issuance_enabled: true,
        };
        (
            authority,
            ocsp,
            descriptor,
            "a-very-long-test-bearer-token-value-123456".into(),
        )
    }

    #[tokio::test]
    async fn replica_receiver_requires_peer_token_and_allowlisted_leader() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = TenantId::new("alpha").unwrap();
        let journal = Arc::new(DurableTenantJournal::open(dir.path(), tenant.clone()).unwrap());
        let node = Arc::new(
            ReplicaNode::new(
                "node-b",
                journal.clone(),
                vec!["node-a".to_owned()],
                "replica-token-that-is-long-enough-123456",
            )
            .unwrap(),
        );
        let app = node.router();
        let request = ReplicaPrepareRequest {
            leader_id: "node-a".into(),
            record: JournalRecord {
                tenant,
                sequence: 1,
                term: 1,
                kind: "test.record".into(),
                payload: vec![1],
                previous_hash: [0; 32],
                hash: [0; 32],
                created_at: 1,
            },
        };
        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/replica/prepare")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let forbidden = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/replica/prepare")
                    .header(
                        "authorization",
                        "Bearer replica-token-that-is-long-enough-123456",
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&ReplicaPrepareRequest {
                            leader_id: "rogue-node".into(),
                            record: request.record.clone(),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::UNAUTHORIZED);
        let mut valid_record = request.record;
        valid_record.hash = test_record_hash(&valid_record);
        let prepare = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/replica/prepare")
                    .header(
                        "authorization",
                        "Bearer replica-token-that-is-long-enough-123456",
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&ReplicaPrepareRequest {
                            leader_id: "node-a".into(),
                            record: valid_record.clone(),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(prepare.status(), StatusCode::NO_CONTENT);
        let commit = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/replica/commit")
                    .header(
                        "authorization",
                        "Bearer replica-token-that-is-long-enough-123456",
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&ReplicaDecisionRequest {
                            leader_id: "node-a".into(),
                            sequence: valid_record.sequence,
                            hash: valid_record.hash,
                            term: valid_record.term,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(commit.status(), StatusCode::NO_CONTENT);
        assert_eq!(journal.committed_records().unwrap(), vec![valid_record]);
    }

    fn test_record_hash(record: &JournalRecord) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"NEXUSQ-HA-JOURNAL-v1\0");
        hasher.update((record.tenant.as_str().len() as u32).to_be_bytes());
        hasher.update(record.tenant.as_str().as_bytes());
        hasher.update(record.sequence.to_be_bytes());
        hasher.update(record.term.to_be_bytes());
        hasher.update((record.kind.len() as u32).to_be_bytes());
        hasher.update(record.kind.as_bytes());
        hasher.update((record.payload.len() as u64).to_be_bytes());
        hasher.update(&record.payload);
        hasher.update(record.previous_hash);
        hasher.update(record.created_at.to_be_bytes());
        hasher.finalize().into()
    }

    #[test]
    fn replica_client_refuses_plaintext_transport() {
        let result = HttpReplicaPeer::new(
            "node-a",
            "node-b",
            "http://node-b.internal/",
            "replica-token-that-is-long-enough-123456".into(),
            b"invalid",
            b"invalid",
        );
        assert!(matches!(result, Err(HaError::InvalidPeerConfig)));
    }

    #[tokio::test]
    async fn routes_are_tenant_scoped_and_enrollment_requires_tenant_token() {
        let dir = tempfile::tempdir().unwrap();
        let (authority, ocsp, descriptor, token) = services(dir.path());
        let catalog = Arc::new(TenantCatalog::open(dir.path().join("tenants.json")).unwrap());
        let registry =
            Arc::new(PkiTenantRegistry::new(catalog, RecoveryObjectives::default()).unwrap());
        registry
            .mount_tenant(descriptor.clone(), authority, ocsp, &token)
            .unwrap();
        let app = registry.clone().router();
        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tenants/alpha/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"principal_id":"device-1","csr_der_base64":"AA=="}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/tenants/beta/crl")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/tenants/alpha/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        let rbac = Arc::new(RbacStore::open(dir.path().join("rbac.json")).unwrap());
        let audit = Arc::new(AuditLog::open(dir.path().join("admin-audit.log"), [4; 32]).unwrap());
        let root_token = format!("root-{}", "r".repeat(48));
        rbac.bootstrap_root(
            "root-admin",
            &root_token,
            std::collections::BTreeSet::from([descriptor.id.clone()]),
            &audit,
        )
        .unwrap();
        let admin_app = registry.clone().router_with_admin(rbac, audit.clone());
        let unauthenticated_admin = admin_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/tenants/alpha")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated_admin.status(), StatusCode::UNAUTHORIZED);
        let disabled = admin_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants/alpha/issuance")
                    .header("authorization", format!("Bearer {root_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::OK);
        let disabled_health = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/tenants/alpha/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled_health.status(), StatusCode::OK);
        let enabled = admin_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants/alpha/issuance")
                    .header("authorization", format!("Bearer {root_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enabled.status(), StatusCode::OK);
        let crl = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/tenants/alpha/crl")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(crl.status(), StatusCode::OK);
        let bad_ocsp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tenants/alpha/ocsp")
                    .body(Body::from(vec![0u8]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_ocsp.status(), StatusCode::BAD_REQUEST);
        let csr_key = SigningKey::<MlDsa65>::generate();
        let mut csr_builder =
            RequestBuilder::new(Name::from_str("CN=service.example.com").unwrap()).unwrap();
        csr_builder
            .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
                Ia5String::new("service.example.com").unwrap(),
            )]))
            .unwrap();
        let csr = csr_builder
            .build::<SigningKey<MlDsa65>, Signature<MlDsa65>>(&csr_key)
            .unwrap()
            .to_der()
            .unwrap();
        let body =
            serde_json::json!({"principal_id":"device-1", "csr_der_base64":STANDARD.encode(csr)})
                .to_string();
        let issued = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tenants/alpha/enroll")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(issued.status(), StatusCode::OK);
        audit.verify().unwrap();
    }
}

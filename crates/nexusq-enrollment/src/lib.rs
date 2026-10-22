//! Policy-controlled post-quantum certificate enrollment.
//!
//! The shared enrollment engine validates PKCS#10 signatures and requested identities before
//! issuing a leaf certificate under an ML-DSA-65 CA. Protocol handlers must authenticate first,
//! then call the same engine so authorization, rate limiting, and audit are consistent.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cms::content_info::ContentInfo;
use const_oid::db::{
    fips204::ID_ML_DSA_65,
    rfc5280::{ID_CE_SUBJECT_ALT_NAME, ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH},
    rfc5912::ID_EXTENSION_REQ,
};
use der::{
    Decode, Encode,
    asn1::{Ia5String, ObjectIdentifier as DerOid},
};
use ml_dsa::{MlDsa65, Signature as MlDsaSignature, SigningKey, VerifyingKey};
use nexusq_ha::{HaCoordinator, HaError, LeadershipLease};
use nexusq_x509::{
    ExternalSignError, MlDsa65Signer, build_certificate_with_external_ml_dsa65_signer,
};
use sha2::{Digest, Sha256};
use signature::Verifier;
use spki::SubjectPublicKeyInfoRef;
use subtle::ConstantTimeEq;
use x509_cert::{
    Certificate,
    builder::{CertificateBuilder, Error as BuilderError, profile::BuilderProfile},
    ext::{
        Extension, ToExtension,
        pkix::{
            AccessDescription, AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints,
            CrlDistributionPoints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
            SubjectKeyIdentifier,
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName},
        },
    },
    name::Name,
    request::{CertReq, ExtensionReq},
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity,
};

const MAX_CSR_BYTES: usize = 1024 * 1024;
const MAX_DNS_NAMES: usize = 32;
const MAX_AUDIT_EVENTS: usize = 10_000;
const ID_AD_OCSP: DerOid = DerOid::new_unwrap("1.3.6.1.5.5.7.48.1");

/// Supported enrollment protocol for audit records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// EST simpleenroll.
    Est,
    /// ACME order finalization.
    Acme,
    /// CMPv2 certificate request.
    Cmpv2,
}

/// Authenticated principal for a certificate enrollment request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    /// Stable account or device identifier.
    pub id: String,
}

/// CA issuance policy.
#[derive(Clone, Debug)]
pub struct EnrollmentPolicy {
    /// Global DNS suffixes permitted for principals without a dedicated allowlist.
    pub allowed_dns_suffixes: Vec<String>,
    /// Optional per-principal DNS suffix allowlists; if present, they replace the global list.
    pub principal_dns_suffixes: HashMap<String, Vec<String>>,
    /// Maximum lifetime of an issued leaf certificate.
    pub max_validity: Duration,
    /// Maximum DNS SANs accepted from a single CSR.
    pub max_dns_names: usize,
    /// Permit issuance for TLS client authentication as well as server authentication.
    pub allow_client_auth: bool,
    /// Optional OCSP URL advertised in AIA.
    pub ocsp_url: Option<String>,
    /// Optional CRL URL advertised in CRL Distribution Points.
    pub crl_url: Option<String>,
    /// Maximum enrollment requests per principal per rolling minute.
    pub requests_per_minute: usize,
}

impl EnrollmentPolicy {
    /// Create a conservative policy with 30-day leaf certificates and 10 requests/minute.
    pub fn new(allowed_dns_suffixes: Vec<String>) -> Result<Self, Error> {
        let policy = Self {
            allowed_dns_suffixes,
            principal_dns_suffixes: HashMap::new(),
            max_validity: Duration::from_secs(30 * 24 * 60 * 60),
            max_dns_names: 10,
            allow_client_auth: false,
            ocsp_url: None,
            crl_url: None,
            requests_per_minute: 10,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate the configured profile before the service starts.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_validity.is_zero()
            || self.max_validity > Duration::from_secs(397 * 24 * 60 * 60)
            || self.max_dns_names == 0
            || self.max_dns_names > MAX_DNS_NAMES
            || self.requests_per_minute == 0
            || self.allowed_dns_suffixes.is_empty()
        {
            return Err(Error::InvalidPolicy);
        }
        for suffix in self
            .allowed_dns_suffixes
            .iter()
            .chain(self.principal_dns_suffixes.values().flatten())
        {
            if !valid_dns_suffix(suffix) {
                return Err(Error::InvalidPolicy);
            }
        }
        if self.ocsp_url.is_some() != self.crl_url.is_some() {
            return Err(Error::InvalidPolicy);
        }
        if self
            .ocsp_url
            .as_deref()
            .is_some_and(|url| !valid_https_url(url))
            || self
                .crl_url
                .as_deref()
                .is_some_and(|url| !valid_https_url(url))
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
}

fn valid_dns_suffix(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains('*')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}
fn valid_https_url(value: &str) -> bool {
    value.is_ascii()
        && !value.chars().any(char::is_whitespace)
        && !value.contains('#')
        && !value.contains('@')
        && value
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.split(['/', '?']).next().unwrap_or_default().is_empty())
}
fn suffix_authorizes(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Audit event emitted for every accepted or denied enrollment attempt.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    /// Unix time in milliseconds.
    pub timestamp_ms: u128,
    /// Authenticated principal identifier.
    pub principal: String,
    /// Protocol adapter that invoked the engine.
    pub protocol: String,
    /// SHA-256 of the request body, never the request itself.
    pub request_sha256: String,
    /// `issued` or a stable denial category.
    pub outcome: String,
    /// Issued certificate serial when successful.
    pub serial: Option<String>,
}

/// Enrollment errors. Public messages are intentionally non-sensitive.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed ASN.1/DER input.
    #[error("invalid certificate request encoding")]
    Der(#[from] der::Error),
    /// CSR signature did not verify.
    #[error("certificate request signature is invalid")]
    InvalidCsrSignature,
    /// CSR key/signature algorithm is not supported by this profile.
    #[error("certificate request algorithm is not supported")]
    UnsupportedAlgorithm,
    /// Requested DNS identity is malformed or outside policy.
    #[error("requested certificate identity is not authorized")]
    UnauthorizedIdentity,
    /// CSR requested extensions or attributes not supported by this profile.
    #[error("certificate request contains unsupported attributes or extensions")]
    UnsupportedCsrFeatures,
    /// CA or issuance policy configuration is invalid.
    #[error("certificate authority or enrollment policy is invalid")]
    InvalidPolicy,
    /// Principal exceeded the rate limit.
    #[error("enrollment rate limit exceeded")]
    RateLimited,
    /// Internal state lock is unavailable.
    #[error("enrollment state unavailable")]
    StateUnavailable,
    /// Durable HA replication/fencing failed; the certificate was not returned to the caller.
    #[error("HA replication failed: {0}")]
    Ha(#[from] HaError),
    /// Certificate issuance failed.
    #[error("certificate issuance failed: {0}")]
    Issuance(#[from] BuilderError),
    /// Certificate signing failed.
    #[error("certificate signing failed")]
    Signing(#[from] signature::Error),
    /// External HSM-backed signing or certificate assembly failed.
    #[error("external certificate signing failed: {0}")]
    ExternalSigning(#[from] ExternalSignError),
}

struct LeafProfile {
    issuer: Name,
    subject: Name,
    dns_names: Vec<String>,
    allow_client_auth: bool,
    ocsp_url: Option<String>,
    crl_url: Option<String>,
}
impl BuilderProfile for LeafProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    #[allow(clippy::vec_init_then_push)] // Extension builders inspect prior extensions for duplicate/ordering constraints.
    fn build_extensions(
        &self,
        spk: spki::SubjectPublicKeyInfoRef<'_>,
        issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::TbsCertificate,
    ) -> Result<Vec<Extension>, BuilderError> {
        let mut extensions = Vec::new();
        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk.clone())?
                .to_extension(tbs.subject(), &extensions)?,
        );
        extensions.push(
            SubjectKeyIdentifier::try_from(spk.clone())?
                .to_extension(tbs.subject(), &extensions)?,
        );
        extensions.push(
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &extensions)?,
        );
        extensions.push(
            KeyUsage(der::flagset::FlagSet::from(KeyUsages::DigitalSignature))
                .to_extension(tbs.subject(), &extensions)?,
        );
        let mut eku = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH]);
        if self.allow_client_auth {
            eku.0.push(ID_KP_CLIENT_AUTH);
        }
        extensions.push(eku.to_extension(tbs.subject(), &extensions)?);
        let sans = self
            .dns_names
            .iter()
            .map(|name| Ia5String::new(name).map(GeneralName::DnsName))
            .collect::<der::Result<Vec<_>>>()?;
        extensions.push(SubjectAltName(sans).to_extension(tbs.subject(), &extensions)?);
        if let (Some(ocsp), Some(crl)) = (&self.ocsp_url, &self.crl_url) {
            let aia = AuthorityInfoAccessSyntax(vec![AccessDescription {
                access_method: ID_AD_OCSP,
                access_location: GeneralName::UniformResourceIdentifier(Ia5String::new(ocsp)?),
            }]);
            extensions.push(aia.to_extension(tbs.subject(), &extensions)?);
            let points = CrlDistributionPoints(vec![DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::UniformResourceIdentifier(Ia5String::new(crl)?),
                ])),
                reasons: None,
                crl_issuer: None,
            }]);
            extensions.push(points.to_extension(tbs.subject(), &extensions)?);
        }
        Ok(extensions)
    }
}

struct HaContext {
    coordinator: Arc<HaCoordinator>,
    lease: RwLock<LeadershipLease>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerialReservation {
    serial: u64,
    principal_id: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct IssuedCertificateRecord {
    serial: u64,
    principal_id: String,
    certificate_der: Vec<u8>,
}

/// Shared issuance engine used by protocol-specific enrollment adapters.
pub struct EnrollmentAuthority {
    issuer_certificate: Certificate,
    issuer_signer: Arc<dyn MlDsa65Signer>,
    policy: EnrollmentPolicy,
    next_serial: AtomicU64,
    rate: Mutex<HashMap<String, VecDeque<Instant>>>,
    audit: RwLock<Vec<AuditEvent>>,
    ha: Option<HaContext>,
}

impl EnrollmentAuthority {
    /// Configure an ML-DSA-65 CA and policy. The CA certificate's public key must match the signer.
    pub fn new(
        issuer_certificate: Certificate,
        issuer_signer: SigningKey<MlDsa65>,
        policy: EnrollmentPolicy,
        first_serial: u64,
    ) -> Result<Self, Error> {
        Self::new_with_signer(
            issuer_certificate,
            Arc::new(issuer_signer),
            policy,
            first_serial,
        )
    }

    /// Configure an ML-DSA-65 CA using an external signer such as a PKCS#11 HSM key handle.
    /// The private key is never imported into this process; only the public key and a sign callback
    /// are used. The CA certificate public key must match the external signer.
    pub fn new_with_signer(
        issuer_certificate: Certificate,
        issuer_signer: Arc<dyn MlDsa65Signer>,
        policy: EnrollmentPolicy,
        first_serial: u64,
    ) -> Result<Self, Error> {
        policy.validate()?;
        let verifying_key = issuer_signer.public_key();
        let spki = SubjectPublicKeyInfoOwned::from_key(&verifying_key)
            .map_err(|_| Error::InvalidPolicy)?;
        if issuer_certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid
            != ID_ML_DSA_65
            || issuer_certificate
                .tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes()
                != spki.subject_public_key.raw_bytes()
        {
            return Err(Error::InvalidPolicy);
        }
        let issuer_extensions = issuer_certificate
            .tbs_certificate()
            .extensions()
            .ok_or(Error::InvalidPolicy)?;
        let is_ca = issuer_extensions.iter().any(|extension| {
            extension.extn_id.to_string() == "2.5.29.19"
                && x509_cert::ext::pkix::BasicConstraints::from_der(extension.extn_value.as_bytes())
                    .is_ok_and(|constraints| constraints.ca)
        });
        let can_sign_certs = issuer_extensions.iter().any(|extension| {
            extension.extn_id.to_string() == "2.5.29.15"
                && KeyUsage::from_der(extension.extn_value.as_bytes())
                    .is_ok_and(|usage| usage.key_cert_sign())
        });
        if !is_ca || !can_sign_certs {
            return Err(Error::InvalidPolicy);
        }
        let now = SystemTime::now();
        let issuer_validity = &issuer_certificate.tbs_certificate().validity();
        if now < issuer_validity.not_before.to_system_time()
            || now >= issuer_validity.not_after.to_system_time()
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(Self {
            issuer_certificate,
            issuer_signer,
            policy,
            next_serial: AtomicU64::new(first_serial.max(1)),
            rate: Mutex::new(HashMap::new()),
            audit: RwLock::new(Vec::new()),
            ha: None,
        })
    }

    /// Configure a CA whose serial reservations and issued certificates are committed through a
    /// tenant-scoped HA coordinator before successful issuance is returned.
    pub fn new_ha(
        issuer_certificate: Certificate,
        issuer_signer: Arc<dyn MlDsa65Signer>,
        policy: EnrollmentPolicy,
        first_serial: u64,
        coordinator: Arc<HaCoordinator>,
        lease: LeadershipLease,
    ) -> Result<Self, Error> {
        lease.validate(coordinator.node_id(), SystemTime::now())?;
        let records = coordinator.committed_records()?;
        let mut next_serial = first_serial.max(1);
        for record in &records {
            let serial = match record.kind.as_str() {
                "ca.serial_reserved" => {
                    serde_json::from_slice::<SerialReservation>(&record.payload)
                        .map(|value| value.serial)
                        .map_err(|_| Error::InvalidPolicy)?
                }
                "ca.certificate_issued" => {
                    serde_json::from_slice::<IssuedCertificateRecord>(&record.payload)
                        .map(|value| value.serial)
                        .map_err(|_| Error::InvalidPolicy)?
                }
                _ => continue,
            };
            next_serial = next_serial.max(serial.checked_add(1).ok_or(Error::InvalidPolicy)?);
        }
        let mut authority =
            Self::new_with_signer(issuer_certificate, issuer_signer, policy, next_serial)?;
        authority.ha = Some(HaContext {
            coordinator,
            lease: RwLock::new(lease),
        });
        Ok(authority)
    }

    /// Replace the current leader lease after the external consensus system renews it. Terms and
    /// fencing epochs may only move forward.
    pub fn update_leadership_lease(&self, lease: LeadershipLease) -> Result<(), Error> {
        let ha = self.ha.as_ref().ok_or(Error::InvalidPolicy)?;
        lease.validate(ha.coordinator.node_id(), SystemTime::now())?;
        let mut current = ha.lease.write().map_err(|_| Error::StateUnavailable)?;
        if lease.term < current.term || lease.fencing_epoch < current.fencing_epoch {
            return Err(Error::Ha(HaError::NotLeader));
        }
        *current = lease;
        Ok(())
    }

    /// Issue a leaf certificate after validating the CSR signature, profile and principal policy.
    pub fn enroll_csr(
        &self,
        principal: &Principal,
        protocol: Protocol,
        csr_der: &[u8],
    ) -> Result<Certificate, Error> {
        let digest = Sha256::digest(csr_der);
        let digest = digest.iter().fold(
            String::with_capacity(digest.len() * 2),
            |mut output, byte| {
                let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"));
                output
            },
        );
        let result = self.enroll_inner(principal, csr_der);
        let (outcome, serial) = match &result {
            Ok(cert) => (
                "issued".to_owned(),
                Some(cert.tbs_certificate().serial_number().to_string()),
            ),
            Err(error) => (error.audit_category().to_owned(), None),
        };
        self.record_audit(AuditEvent {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            principal: principal.id.clone(),
            protocol: format!("{protocol:?}").to_ascii_lowercase(),
            request_sha256: digest,
            outcome,
            serial,
        });
        result
    }

    fn enroll_inner(&self, principal: &Principal, csr_der: &[u8]) -> Result<Certificate, Error> {
        if csr_der.is_empty() || csr_der.len() > MAX_CSR_BYTES {
            return Err(Error::UnsupportedCsrFeatures);
        }
        self.check_rate_limit(&principal.id)?;
        let csr = CertReq::from_der(csr_der)?;
        if csr.info.public_key.algorithm.oid != ID_ML_DSA_65 || csr.algorithm.oid != ID_ML_DSA_65 {
            return Err(Error::UnsupportedAlgorithm);
        }
        let spki_der = csr.info.public_key.to_der()?;
        let spki_ref = SubjectPublicKeyInfoRef::from_der(&spki_der)?;
        let verifying_key =
            VerifyingKey::<MlDsa65>::try_from(spki_ref).map_err(|_| Error::UnsupportedAlgorithm)?;
        let signature_bytes = csr.signature.as_bytes().ok_or(Error::InvalidCsrSignature)?;
        let signature = MlDsaSignature::<MlDsa65>::try_from(signature_bytes)
            .map_err(|_| Error::InvalidCsrSignature)?;
        verifying_key
            .verify(&csr.info.to_der()?, &signature)
            .map_err(|_| Error::InvalidCsrSignature)?;
        if csr.info.subject.is_empty() {
            return Err(Error::UnauthorizedIdentity);
        }
        let dns_names = requested_dns_names(&csr)?;
        if dns_names.is_empty() || dns_names.len() > self.policy.max_dns_names {
            return Err(Error::UnauthorizedIdentity);
        }
        let allowed = self
            .policy
            .principal_dns_suffixes
            .get(&principal.id)
            .unwrap_or(&self.policy.allowed_dns_suffixes);
        for name in &dns_names {
            if !valid_dns_name(name)
                || !allowed.iter().any(|suffix| suffix_authorizes(name, suffix))
            {
                return Err(Error::UnauthorizedIdentity);
            }
        }
        let serial = self
            .next_serial
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map_err(|_| Error::InvalidPolicy)?;
        if let Some(ha) = &self.ha {
            let reservation = serde_json::to_vec(&SerialReservation {
                serial,
                principal_id: principal.id.clone(),
            })
            .map_err(|_| Error::StateUnavailable)?;
            let lease = ha
                .lease
                .read()
                .map_err(|_| Error::StateUnavailable)?
                .clone();
            ha.coordinator
                .commit(&lease, "ca.serial_reserved", &reservation)?;
        }
        let profile = LeafProfile {
            issuer: self.issuer_certificate.tbs_certificate().subject().clone(),
            subject: csr.info.subject,
            dns_names,
            allow_client_auth: self.policy.allow_client_auth,
            ocsp_url: self.policy.ocsp_url.clone(),
            crl_url: self.policy.crl_url.clone(),
        };
        let ca_remaining = self
            .issuer_certificate
            .tbs_certificate()
            .validity()
            .not_after
            .to_system_time()
            .duration_since(SystemTime::now())
            .map_err(|_| Error::InvalidPolicy)?;
        let leaf_validity = self.policy.max_validity.min(ca_remaining);
        if leaf_validity.is_zero() {
            return Err(Error::InvalidPolicy);
        }
        let builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(serial),
            Validity::from_now(leaf_validity).map_err(|_| Error::InvalidPolicy)?,
            csr.info.public_key,
        )?;
        let certificate = build_certificate_with_external_ml_dsa65_signer(
            builder,
            self.issuer_signer.public_key(),
            |tbs_der| self.issuer_signer.sign(tbs_der),
        )?;
        if let Some(ha) = &self.ha {
            let record = IssuedCertificateRecord {
                serial,
                principal_id: principal.id.clone(),
                certificate_der: certificate.to_der()?,
            };
            let payload = serde_json::to_vec(&record).map_err(|_| Error::StateUnavailable)?;
            let lease = ha
                .lease
                .read()
                .map_err(|_| Error::StateUnavailable)?
                .clone();
            ha.coordinator
                .commit(&lease, "ca.certificate_issued", &payload)?;
        }
        Ok(certificate)
    }

    fn check_rate_limit(&self, principal: &str) -> Result<(), Error> {
        let now = Instant::now();
        let mut entries = self.rate.lock().map_err(|_| Error::StateUnavailable)?;
        entries.retain(|_, history| {
            history
                .back()
                .is_some_and(|last| now.duration_since(*last) < Duration::from_secs(60))
        });
        if entries.len() >= 100_000 && !entries.contains_key(principal) {
            return Err(Error::RateLimited);
        }
        let history = entries.entry(principal.to_owned()).or_default();
        while history
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            history.pop_front();
        }
        if history.len() >= self.policy.requests_per_minute {
            return Err(Error::RateLimited);
        }
        history.push_back(now);
        Ok(())
    }

    fn record_audit(&self, event: AuditEvent) {
        let mut audit = self
            .audit
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if audit.len() >= MAX_AUDIT_EVENTS {
            audit.remove(0);
        }
        audit.push(event);
    }

    /// Return a snapshot of recent audit events. The host should forward these to durable audit storage.
    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.audit
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// CA certificate used by EST `/cacerts` and protocol adapters.
    pub fn issuer_certificate(&self) -> &Certificate {
        &self.issuer_certificate
    }

    /// HA coordinator when this authority is configured for replicated issuance.
    pub fn ha_coordinator(&self) -> Option<&Arc<HaCoordinator>> {
        self.ha.as_ref().map(|ha| &ha.coordinator)
    }
    /// Tenant journal namespace when this authority is HA-enabled.
    pub fn ha_tenant_id(&self) -> Option<&nexusq_ha::TenantId> {
        self.ha.as_ref().map(|ha| ha.coordinator.tenant())
    }

    /// Build the EST router. Basic credentials are supplied as username/password pairs and stored as hashes.
    pub fn est_router(self: Arc<Self>, credentials: EstCredentials) -> Router {
        Router::new()
            .route("/.well-known/est/simpleenroll", post(est_simple_enroll))
            .route("/.well-known/est/cacerts", get(est_ca_certs))
            .route("/.well-known/est/csrattrs", get(est_csr_attrs))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_CSR_BYTES))
            .with_state(EstState {
                authority: self,
                credentials: Arc::new(credentials),
            })
    }
}

fn valid_dns_name(name: &str) -> bool {
    if !name.is_ascii() || name.len() > 253 || name.starts_with("*.") || name.ends_with('.') {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn requested_dns_names(csr: &CertReq) -> Result<Vec<String>, Error> {
    let mut requested_extensions = None;
    for attribute in csr.info.attributes.iter() {
        if attribute.oid == ID_EXTENSION_REQ {
            if requested_extensions.is_some() {
                return Err(Error::UnsupportedCsrFeatures);
            }
            if attribute.values.len() != 1 {
                return Err(Error::UnsupportedCsrFeatures);
            }
            let value = attribute
                .values
                .iter()
                .next()
                .ok_or(Error::UnsupportedCsrFeatures)?;
            requested_extensions = Some(value.decode_as::<ExtensionReq>()?);
        } else {
            return Err(Error::UnsupportedCsrFeatures);
        }
    }
    let extensions = requested_extensions.ok_or(Error::UnauthorizedIdentity)?;
    let mut names = None;
    for extension in extensions.0 {
        if extension.extn_id != ID_CE_SUBJECT_ALT_NAME || names.is_some() || extension.critical {
            return Err(Error::UnsupportedCsrFeatures);
        }
        let san = SubjectAltName::from_der(extension.extn_value.as_bytes())?;
        let mut dns = Vec::new();
        for name in san.0 {
            match name {
                GeneralName::DnsName(value) => dns.push(value.as_str().to_ascii_lowercase()),
                _ => return Err(Error::UnsupportedCsrFeatures),
            }
        }
        names = Some(dns);
    }
    names.ok_or(Error::UnauthorizedIdentity)
}

impl Error {
    fn audit_category(&self) -> &'static str {
        match self {
            Self::InvalidCsrSignature => "invalid_csr_signature",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::UnauthorizedIdentity => "unauthorized_identity",
            Self::UnsupportedCsrFeatures => "unsupported_csr_features",
            Self::RateLimited => "rate_limited",
            Self::InvalidPolicy => "invalid_policy",
            Self::StateUnavailable => "state_unavailable",
            Self::Ha(_) => "ha_replication_failed",
            Self::Der(_) => "invalid_der",
            Self::Issuance(_) => "issuance_failed",
            Self::Signing(_) | Self::ExternalSigning(_) => "signing_failed",
        }
    }
}

/// Hashed HTTP Basic credentials for EST. Plaintext passwords are never stored or logged.
pub struct EstCredentials {
    users: HashMap<String, [u8; 32]>,
}
impl EstCredentials {
    /// Build a credential map from configured username/password pairs.
    pub fn new<I, U, P>(credentials: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (U, P)>,
        U: Into<String>,
        P: Into<String>,
    {
        let mut users = HashMap::new();
        for (username, password) in credentials {
            let username = username.into();
            let password = password.into();
            if username.is_empty() || password.is_empty() {
                return Err(Error::InvalidPolicy);
            }
            let digest = Sha256::digest(format!("{username}:{password}").as_bytes()).into();
            if users.insert(username, digest).is_some() {
                return Err(Error::InvalidPolicy);
            }
        }
        if users.is_empty() {
            return Err(Error::InvalidPolicy);
        }
        Ok(Self { users })
    }
    fn authenticate(&self, header_value: Option<&str>) -> Option<Principal> {
        let encoded = header_value?.strip_prefix("Basic ")?;
        let decoded = STANDARD.decode(encoded).ok()?;
        let decoded = std::str::from_utf8(&decoded).ok()?;
        let (username, password) = decoded.split_once(':')?;
        let candidate: [u8; 32] =
            Sha256::digest(format!("{username}:{password}").as_bytes()).into();
        let expected = self.users.get(username)?;
        bool::from(candidate.ct_eq(expected)).then(|| Principal {
            id: username.to_owned(),
        })
    }
}

#[derive(Clone)]
struct EstState {
    authority: Arc<EnrollmentAuthority>,
    credentials: Arc<EstCredentials>,
}

async fn est_simple_enroll(
    State(state): State<EstState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    if !headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| value.starts_with("application/pkcs10"))
    {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected application/pkcs10",
        )
            .into_response();
    }
    let Some(principal) = state.credentials.authenticate(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
    ) else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"NexusQ EST\"")],
            "authentication required",
        )
            .into_response();
    };
    let csr_der = match STANDARD.decode(body.as_ref()) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid PKCS#10 encoding").into_response(),
    };
    match state
        .authority
        .enroll_csr(&principal, Protocol::Est, &csr_der)
    {
        Ok(certificate) => {
            match ContentInfo::try_from(x509_cert::PkiPath::from(vec![
                certificate,
                state.authority.issuer_certificate().clone(),
            ]))
            .and_then(|content| content.to_der())
            {
                Ok(cms) => (
                    StatusCode::OK,
                    [(
                        header::CONTENT_TYPE,
                        "application/pkcs7-mime; smime-type=certs-only",
                    )],
                    cms,
                )
                    .into_response(),
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "certificate packaging failed",
                )
                    .into_response(),
            }
        }
        Err(Error::RateLimited) => (
            StatusCode::TOO_MANY_REQUESTS,
            "enrollment rate limit exceeded",
        )
            .into_response(),
        Err(Error::StateUnavailable | Error::Ha(_) | Error::Issuance(_) | Error::Signing(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "certificate issuance failed",
        )
            .into_response(),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            "certificate request rejected by policy",
        )
            .into_response(),
    }
}

async fn est_ca_certs(
    State(state): State<EstState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if state
        .credentials
        .authenticate(
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
        )
        .is_none()
    {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"NexusQ EST\"")],
            "authentication required",
        )
            .into_response();
    }
    match ContentInfo::try_from(state.authority.issuer_certificate().clone())
        .and_then(|content| content.to_der())
    {
        Ok(cms) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/pkcs7-mime; smime-type=certs-only",
            )],
            STANDARD.encode(cms),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "CA certificate packaging failed",
        )
            .into_response(),
    }
}

async fn est_csr_attrs(
    State(state): State<EstState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if state
        .credentials
        .authenticate(
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
        )
        .is_none()
    {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"NexusQ EST\"")],
            "authentication required",
        )
            .into_response();
    }
    // Empty CSR attributes are valid: the server accepts a CSR carrying SAN and enforces policy at enrollment.
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/csrattrs")],
        STANDARD.encode([0x30u8, 0x00u8]),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use cms::content_info::ContentInfo;
    use der::{Decode, Encode, asn1::Ia5String};
    use ml_dsa::{Generate, Keypair};
    use std::str::FromStr;
    use tower::ServiceExt;
    use x509_cert::{
        builder::{Builder, CertificateBuilder, profile::cabf},
        ext::pkix::{SubjectAltName, name::GeneralName},
        request::RequestBuilder,
        spki::SubjectPublicKeyInfoOwned,
        time::Validity,
    };

    fn fixture(san: &str) -> (Arc<EnrollmentAuthority>, SigningKey<MlDsa65>, Vec<u8>) {
        let ca_key = SigningKey::<MlDsa65>::generate();
        let ca_subject = Name::from_str("CN=NexusQ Enrollment Test Root,O=NexusQ,C=US").unwrap();
        let profile = cabf::Root::new(false, ca_subject).unwrap();
        let ca_spki = SubjectPublicKeyInfoOwned::from_key(&ca_key.verifying_key()).unwrap();
        let ca_builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60)).unwrap(),
            ca_spki,
        )
        .unwrap();
        let ca_cert = ca_builder
            .build::<SigningKey<MlDsa65>, MlDsaSignature<MlDsa65>>(&ca_key)
            .unwrap();
        let mut policy = EnrollmentPolicy::new(vec!["example.com".to_owned()]).unwrap();
        policy.ocsp_url = Some("https://pki.example.com/ocsp".to_owned());
        policy.crl_url = Some("https://pki.example.com/crl".to_owned());
        policy.validate().unwrap();
        let authority = Arc::new(EnrollmentAuthority::new(ca_cert, ca_key, policy, 100).unwrap());
        let csr_key = SigningKey::<MlDsa65>::generate();
        let subject = Name::from_str(&format!("CN={san}")).unwrap();
        let mut request = RequestBuilder::new(subject).unwrap();
        request
            .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
                Ia5String::new(san).unwrap(),
            )]))
            .unwrap();
        let csr = request
            .build::<SigningKey<MlDsa65>, MlDsaSignature<MlDsa65>>(&csr_key)
            .unwrap();
        (authority, csr_key, csr.to_der().unwrap())
    }

    #[test]
    fn ha_enrollment_persists_serial_reservations_across_authority_restart() {
        use nexusq_ha::{DurableTenantJournal, HaCoordinator, LeadershipLease, TenantId};
        use std::time::{SystemTime, UNIX_EPOCH};
        let dir = tempfile::tempdir().unwrap();
        let ca_key = SigningKey::<MlDsa65>::generate();
        let ca_subject = Name::from_str("CN=NexusQ HA Test Root,O=NexusQ,C=US").unwrap();
        let profile = cabf::Root::new(false, ca_subject).unwrap();
        let ca_spki = SubjectPublicKeyInfoOwned::from_key(&ca_key.verifying_key()).unwrap();
        let ca_builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60)).unwrap(),
            ca_spki,
        )
        .unwrap();
        let ca_cert = ca_builder
            .build::<SigningKey<MlDsa65>, MlDsaSignature<MlDsa65>>(&ca_key)
            .unwrap();
        let policy = EnrollmentPolicy::new(vec!["example.com".to_owned()]).unwrap();
        let journal = Arc::new(
            DurableTenantJournal::open(dir.path(), TenantId::new("alpha").unwrap()).unwrap(),
        );
        let coordinator = Arc::new(HaCoordinator::new("node-a", journal, vec![]).unwrap());
        let lease = LeadershipLease {
            leader_id: "node-a".into(),
            term: 1,
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 300,
            fencing_epoch: 1,
        };
        let signer: Arc<dyn MlDsa65Signer> = Arc::new(ca_key.clone());
        let first = EnrollmentAuthority::new_ha(
            ca_cert.clone(),
            signer.clone(),
            policy.clone(),
            100,
            coordinator.clone(),
            lease.clone(),
        )
        .unwrap();
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
            .unwrap()
            .to_der()
            .unwrap();
        let principal = Principal {
            id: "device-ha".into(),
        };
        let cert_one = first.enroll_csr(&principal, Protocol::Est, &csr).unwrap();
        assert_eq!(
            cert_one.tbs_certificate().serial_number(),
            &SerialNumber::from(100u32)
        );
        drop(first);
        let second =
            EnrollmentAuthority::new_ha(ca_cert, signer, policy, 100, coordinator, lease).unwrap();
        let cert_two = second.enroll_csr(&principal, Protocol::Est, &csr).unwrap();
        assert_eq!(
            cert_two.tbs_certificate().serial_number(),
            &SerialNumber::from(101u32)
        );
        assert_eq!(second.audit_events().last().unwrap().outcome, "issued");
    }

    #[test]
    fn validates_and_issues_pqc_leaf_certificate_with_revocation_extensions() {
        let (authority, _, csr) = fixture("service.example.com");
        let cert = authority
            .enroll_csr(
                &Principal {
                    id: "device-1".into(),
                },
                Protocol::Est,
                &csr,
            )
            .unwrap();
        assert_eq!(
            cert.tbs_certificate()
                .subject_public_key_info()
                .algorithm
                .oid,
            ID_ML_DSA_65
        );
        let extensions = cert.tbs_certificate().extensions().unwrap();
        assert!(
            extensions
                .iter()
                .any(|e| e.extn_id.to_string() == "2.5.29.17")
        );
        assert!(
            extensions
                .iter()
                .any(|e| e.extn_id.to_string() == "1.3.6.1.5.5.7.1.1")
        );
        assert!(
            extensions
                .iter()
                .any(|e| e.extn_id.to_string() == "2.5.29.31")
        );
        assert_eq!(authority.audit_events().last().unwrap().outcome, "issued");
    }

    #[test]
    fn rejects_tampered_csr_and_unauthorized_dns_name() {
        let (authority, _, mut csr) = fixture("service.example.com");
        let last = csr.len() - 1;
        csr[last] ^= 1;
        assert!(matches!(
            authority.enroll_csr(
                &Principal {
                    id: "device-1".into()
                },
                Protocol::Est,
                &csr
            ),
            Err(Error::InvalidCsrSignature)
        ));
        let (authority, _, csr) = fixture("attacker.invalid");
        assert!(matches!(
            authority.enroll_csr(
                &Principal {
                    id: "device-1".into()
                },
                Protocol::Est,
                &csr
            ),
            Err(Error::UnauthorizedIdentity)
        ));
    }

    #[tokio::test]
    async fn est_requires_auth_and_returns_cms_certificate_chain() {
        use http_body_util::BodyExt;
        let (authority, _, csr) = fixture("service.example.com");
        let credentials = EstCredentials::new([("device-1", "not-logged-secret")]).unwrap();
        let app = authority.clone().est_router(credentials);
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/est/simpleenroll")
                    .header(header::CONTENT_TYPE, "application/pkcs10")
                    .body(Body::from(STANDARD.encode(&csr)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let auth = STANDARD.encode("device-1:not-logged-secret");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/est/simpleenroll")
                    .header(header::CONTENT_TYPE, "application/pkcs10")
                    .header(header::AUTHORIZATION, format!("Basic {auth}"))
                    .body(Body::from(STANDARD.encode(&csr)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("application/pkcs7-mime")
        );
        let cms_der = response.into_body().collect().await.unwrap().to_bytes();
        let cms = ContentInfo::from_der(&cms_der).unwrap();
        assert_eq!(cms.content_type.to_string(), "1.2.840.113549.1.7.2");
    }
}

mod acme;
pub use acme::AcmeChallengeValidator;

mod cmpv2;
pub use cmpv2::CmpCredentials;

//! Post-quantum OCSP response generation and X.509 CRL encoding.
//!
//! The responder is a library component: applications provide a durable revocation store and
//! expose DER responses/CRLs at their chosen HTTP endpoints. Missing serials are reported as
//! `unknown`, never `good`. The in-memory store is a reference implementation, not persistence.

use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use const_oid::{ObjectIdentifier, db::rfc6960::ID_PKIX_OCSP_NONCE};
use der::{
    Choice, Decode, Encode, Enumerated, Sequence,
    asn1::{Any, BitString, GeneralizedTime, Null, OctetString},
};
use ml_dsa::{MlDsa65, SigningKey};
use nexusq_ha::{HaCoordinator, HaError, LeadershipLease};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use signature::Signer;
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};
use x509_cert::{
    Certificate, Version,
    crl::{CertificateList, RevokedCert, TbsCertList},
    ext::{Extensions, ToExtension, pkix::crl::CrlNumber},
    name::Name,
    serial_number::SerialNumber,
    time::Time,
};

/// Maximum number of certificate IDs accepted in one OCSP request.
pub const MAX_OCSP_REQUESTS: usize = 16;
/// Maximum validity window for a generated OCSP response or CRL.
pub const MAX_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);
const ID_PKIX_OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct CertId {
    hash_algorithm: AlgorithmIdentifierOwned,
    issuer_name_hash: OctetString,
    issuer_key_hash: OctetString,
    serial_number: SerialNumber,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct OcspRequest {
    tbs_request: TbsRequest,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    optional_signature: Option<Any>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Sequence)]
struct TbsRequest {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    version: Option<der::asn1::Uint>,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    requestor_name: Option<Any>,
    request_list: Vec<RequestItem>,
    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    request_extensions: Option<Extensions>,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct RequestItem {
    req_cert: CertId,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    single_request_extensions: Option<Extensions>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
#[repr(u8)]
enum ResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct OcspResponse {
    response_status: ResponseStatus,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    response_bytes: Option<ResponseBytes>,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ResponseBytes {
    response_type: ObjectIdentifier,
    response: OctetString,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct BasicOcspResponse {
    tbs_response_data: ResponseData,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    certs: Option<Vec<Certificate>>,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ResponseData {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    version: Option<der::asn1::Uint>,
    responder_id: ResponderId,
    produced_at: GeneralizedTime,
    responses: Vec<SingleResponse>,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    response_extensions: Option<Extensions>,
}
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name),
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(OctetString),
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SingleResponse {
    cert_id: CertId,
    cert_status: CertStatus,
    this_update: GeneralizedTime,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    next_update: Option<GeneralizedTime>,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    single_extensions: Option<Extensions>,
}
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(Null),
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct RevokedInfo {
    revocation_time: GeneralizedTime,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    revocation_reason: Option<x509_cert::ext::pkix::crl::CrlReason>,
}

/// Current state of a certificate known to this responder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateStatus {
    /// The issuer explicitly knows this certificate and has not revoked it.
    Good,
    /// The certificate was revoked at the specified time, optionally with a standard reason.
    Revoked {
        at: SystemTime,
        reason: Option<x509_cert::ext::pkix::crl::CrlReason>,
    },
}

/// In-memory serial-number index. Production deployments should use a durable CA database.
#[derive(Clone, Debug, Default)]
pub struct RevocationStore {
    entries: HashMap<Vec<u8>, CertificateStatus>,
}
impl RevocationStore {
    /// Create an empty store. All unknown serials produce OCSP `unknown`.
    pub fn new() -> Self {
        Self::default()
    }
    /// Mark a certificate as known and not revoked.
    pub fn mark_good(&mut self, serial: &SerialNumber) -> Result<(), Error> {
        self.entries
            .insert(serial.to_der()?, CertificateStatus::Good);
        Ok(())
    }
    /// Revoke a certificate. Persist the updated store before publishing a refreshed CRL.
    pub fn revoke(
        &mut self,
        serial: &SerialNumber,
        at: SystemTime,
        reason: Option<x509_cert::ext::pkix::crl::CrlReason>,
    ) -> Result<(), Error> {
        self.entries
            .insert(serial.to_der()?, CertificateStatus::Revoked { at, reason });
        Ok(())
    }
    /// Return a known status by certificate serial number.
    pub fn get(&self, serial: &SerialNumber) -> Result<Option<&CertificateStatus>, Error> {
        Ok(self.entries.get(&serial.to_der()?))
    }
    fn revoked_entries(
        &self,
    ) -> Result<
        Vec<(
            SerialNumber,
            SystemTime,
            Option<x509_cert::ext::pkix::crl::CrlReason>,
        )>,
        Error,
    > {
        let mut entries = Vec::new();
        for (encoded, status) in &self.entries {
            if let CertificateStatus::Revoked { at, reason } = status {
                entries.push((SerialNumber::from_der(encoded)?, *at, *reason));
            }
        }
        Ok(entries)
    }
}

/// Errors returned by the OCSP and CRL issuer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// ASN.1 DER encoding or decoding failed.
    #[error("DER encoding error: {0}")]
    Der(#[from] der::Error),
    /// Request is empty or exceeds the configured work limit.
    #[error("OCSP request must contain between 1 and {MAX_OCSP_REQUESTS} certificate IDs")]
    InvalidRequestSize,
    /// Request uses an unsupported CertID digest.
    #[error("unsupported OCSP CertID hash algorithm")]
    UnsupportedHashAlgorithm,
    /// CertID issuer name/key hashes do not identify the configured issuer.
    #[error("OCSP CertID does not identify the configured issuer")]
    IssuerMismatch,
    /// Current time could not be represented as ASN.1 GeneralizedTime.
    #[error("system time is outside the supported ASN.1 range")]
    InvalidTime,
    /// Signing failed.
    #[error("signature generation failed: {0}")]
    Signature(#[from] signature::Error),
    /// The selected signer cannot provide a supported signature algorithm identifier.
    #[error("signature algorithm identifier could not be encoded")]
    AlgorithmIdentifier,
    /// The in-memory revocation store lock was poisoned.
    #[error("revocation store unavailable")]
    StoreUnavailable,
    /// Durable HA replication or leader fencing failed.
    #[error("HA replication failed: {0}")]
    Ha(#[from] HaError),
    /// Replicated OCSP mutation could not be decoded.
    #[error("replicated OCSP state is corrupt")]
    ReplicatedStateCorrupt,
    /// Signed requests, requestor names, or unsupported critical extensions are rejected.
    #[error("OCSP request uses an unsupported signed-request or critical-extension feature")]
    UnsupportedRequestFeatures,
}

fn generalized_time(at: SystemTime) -> Result<GeneralizedTime, Error> {
    GeneralizedTime::from_system_time(at).map_err(|_| Error::InvalidTime)
}
fn validate_issuer(cert_id: &CertId, issuer: &Certificate) -> Result<(), Error> {
    let (name_hash, key_hash) = if cert_id.hash_algorithm.oid.to_string() == "1.3.14.3.2.26" {
        (
            Sha1::digest(issuer.tbs_certificate().subject().to_der()?).to_vec(),
            Sha1::digest(
                issuer
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes(),
            )
            .to_vec(),
        )
    } else if cert_id.hash_algorithm.oid.to_string() == "2.16.840.1.101.3.4.2.1" {
        (
            Sha256::digest(issuer.tbs_certificate().subject().to_der()?).to_vec(),
            Sha256::digest(
                issuer
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes(),
            )
            .to_vec(),
        )
    } else {
        return Err(Error::UnsupportedHashAlgorithm);
    };
    if name_hash.as_slice() != cert_id.issuer_name_hash.as_bytes()
        || key_hash.as_slice() != cert_id.issuer_key_hash.as_bytes()
    {
        return Err(Error::IssuerMismatch);
    }
    Ok(())
}

/// Parse a DER OCSP request and return a DER-encoded, ML-DSA-65-signed OCSP response.
/// SHA-1 and SHA-256 CertID hashes are supported for RFC 6960 interoperability; SHA-1 is only
/// used for CertID issuer identification, not for the response signature. The optional nonce is
/// echoed. The caller must ensure the signing key corresponds to the supplied issuer certificate.
pub fn respond_ml_dsa65(
    request_der: &[u8],
    issuer_certificate: &Certificate,
    issuer_signer: &SigningKey<MlDsa65>,
    store: &RevocationStore,
) -> Result<Vec<u8>, Error> {
    if request_der.len() > 1024 * 1024 {
        return Err(Error::InvalidRequestSize);
    }
    let request = OcspRequest::from_der(request_der)?;
    if request.optional_signature.is_some() || request.tbs_request.requestor_name.is_some() {
        return Err(Error::UnsupportedRequestFeatures);
    }
    if request
        .tbs_request
        .request_extensions
        .as_ref()
        .is_some_and(|exts| {
            exts.iter()
                .any(|e| e.critical && e.extn_id != ID_PKIX_OCSP_NONCE)
        })
    {
        return Err(Error::UnsupportedRequestFeatures);
    }
    if request
        .tbs_request
        .version
        .as_ref()
        .is_some_and(|version| !version.is_empty())
    {
        return Err(Error::UnsupportedRequestFeatures);
    }
    let requests = &request.tbs_request.request_list;
    if requests.is_empty() || requests.len() > MAX_OCSP_REQUESTS {
        return Err(Error::InvalidRequestSize);
    }
    let now = SystemTime::now();
    let produced_at = generalized_time(now)?;
    let next_update = generalized_time(now.checked_add(MAX_VALIDITY).ok_or(Error::InvalidTime)?)?;
    let mut responses = Vec::with_capacity(requests.len());
    for item in requests {
        if item
            .single_request_extensions
            .as_ref()
            .is_some_and(|exts| !exts.is_empty())
        {
            return Err(Error::UnsupportedRequestFeatures);
        }
        validate_issuer(&item.req_cert, issuer_certificate)?;
        let cert_status = match store.get(&item.req_cert.serial_number)? {
            Some(CertificateStatus::Good) => CertStatus::Good(Null),
            Some(CertificateStatus::Revoked { at, reason }) => CertStatus::Revoked(RevokedInfo {
                revocation_time: generalized_time(*at)?,
                revocation_reason: *reason,
            }),
            None => CertStatus::Unknown(Null),
        };
        responses.push(SingleResponse {
            cert_id: item.req_cert.clone(),
            cert_status,
            this_update: produced_at,
            next_update: Some(next_update),
            single_extensions: None,
        });
    }
    let response_extensions = request
        .tbs_request
        .request_extensions
        .as_ref()
        .and_then(|exts| exts.iter().find(|e| e.extn_id == ID_PKIX_OCSP_NONCE))
        .cloned()
        .map(|e| vec![e]);
    let tbs = ResponseData {
        version: None,
        responder_id: ResponderId::ByName(issuer_certificate.tbs_certificate().subject().clone()),
        produced_at,
        responses,
        response_extensions,
    };
    let signature_algorithm = issuer_signer
        .signature_algorithm_identifier()
        .map_err(|_| Error::AlgorithmIdentifier)?;
    let signature = issuer_signer.try_sign(&tbs.to_der()?)?.to_bitstring()?;
    let basic = BasicOcspResponse {
        tbs_response_data: tbs,
        signature_algorithm,
        signature,
        certs: Some(vec![issuer_certificate.clone()]),
    };
    let response = OcspResponse {
        response_status: ResponseStatus::Successful,
        response_bytes: Some(ResponseBytes {
            response_type: ID_PKIX_OCSP_BASIC,
            response: OctetString::new(basic.to_der()?)?,
        }),
    };
    Ok(response.to_der()?)
}

/// Create a signed DER X.509 CRL (RFC 5280) using an ML-DSA-65 CA key.
/// `crl_number` must increase monotonically for every CRL issued by this CA.
pub fn build_ml_dsa65_crl(
    issuer: &Name,
    signer: &SigningKey<MlDsa65>,
    store: &RevocationStore,
    crl_number: u64,
) -> Result<Vec<u8>, Error> {
    let now = Time::now().map_err(Error::Der)?;
    let next = time_to_x509(
        SystemTime::now()
            .checked_add(MAX_VALIDITY)
            .ok_or(Error::InvalidTime)?,
    )?;
    let mut revoked = Vec::new();
    for (serial_number, at, reason) in store.revoked_entries()? {
        let mut extensions: Extensions = Vec::new();
        if let Some(reason) = reason {
            extensions.push(reason.to_extension(issuer, &[])?);
        }
        revoked.push(RevokedCert {
            serial_number,
            revocation_date: time_to_x509(at)?,
            crl_entry_extensions: if extensions.is_empty() {
                None
            } else {
                Some(extensions)
            },
        });
    }
    let number = CrlNumber::try_from(crl_number)?;
    let crl_number_extension = number.to_extension(issuer, &[])?;
    let algorithm = signer
        .signature_algorithm_identifier()
        .map_err(|_| Error::AlgorithmIdentifier)?;
    let tbs = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer: issuer.clone(),
        this_update: now,
        next_update: Some(next),
        revoked_certificates: if revoked.is_empty() {
            None
        } else {
            Some(revoked)
        },
        crl_extensions: Some(vec![crl_number_extension]),
    };
    let signature = signer.try_sign(&tbs.to_der()?)?.to_bitstring()?;
    let crl = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: algorithm,
        signature,
    };
    Ok(crl.to_der()?)
}
fn reason_from_code(code: u32) -> Result<x509_cert::ext::pkix::crl::CrlReason, ()> {
    use x509_cert::ext::pkix::crl::CrlReason;
    match code {
        0 => Ok(CrlReason::Unspecified),
        1 => Ok(CrlReason::KeyCompromise),
        2 => Ok(CrlReason::CaCompromise),
        3 => Ok(CrlReason::AffiliationChanged),
        4 => Ok(CrlReason::Superseded),
        5 => Ok(CrlReason::CessationOfOperation),
        6 => Ok(CrlReason::CertificateHold),
        8 => Ok(CrlReason::RemoveFromCRL),
        9 => Ok(CrlReason::PrivilegeWithdrawn),
        10 => Ok(CrlReason::AaCompromise),
        _ => Err(()),
    }
}

fn time_to_x509(at: SystemTime) -> Result<Time, Error> {
    at.try_into().map_err(|_| Error::InvalidTime)
}

/// Decode the successful OCSP response envelope for diagnostics and integration tests.
pub fn validate_response_envelope(response_der: &[u8]) -> Result<(), Error> {
    let response = OcspResponse::from_der(response_der)?;
    if response.response_status != ResponseStatus::Successful || response.response_bytes.is_none() {
        return Err(Error::InvalidRequestSize);
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OcspMutation {
    serial_der: Vec<u8>,
    state: OcspMutationState,
    crl_number: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum OcspMutationState {
    Good,
    Revoked {
        at_unix_secs: u64,
        reason_code: Option<u32>,
    },
}
struct OcspHaContext {
    coordinator: Arc<HaCoordinator>,
    lease: RwLock<LeadershipLease>,
}

/// HTTP responder with `POST /ocsp` and `GET /crl` endpoints.
///
/// Responses use `application/ocsp-response`; CRLs use `application/pkix-crl`. Status updates
/// increment the CRL number so caches can distinguish a newly published list. The service uses
/// an in-memory lock for this reference implementation; durable storage and multi-node replication
/// must be supplied by the deployment before production use.
pub struct OcspService {
    issuer_certificate: Certificate,
    signer: SigningKey<MlDsa65>,
    store: RwLock<RevocationStore>,
    crl_number: AtomicU64,
    ha: Option<OcspHaContext>,
}

impl OcspService {
    /// Construct an HTTP service. The signer must match and be authorized by the issuer cert.
    pub fn new(
        issuer_certificate: Certificate,
        signer: SigningKey<MlDsa65>,
        store: RevocationStore,
        initial_crl_number: u64,
    ) -> Self {
        Self {
            issuer_certificate,
            signer,
            store: RwLock::new(store),
            crl_number: AtomicU64::new(initial_crl_number),
            ha: None,
        }
    }

    /// Construct an HA-enabled responder. The tenant journal is replayed before the service is returned.
    pub fn new_ha(
        issuer_certificate: Certificate,
        signer: SigningKey<MlDsa65>,
        store: RevocationStore,
        initial_crl_number: u64,
        coordinator: Arc<HaCoordinator>,
        lease: LeadershipLease,
    ) -> Result<Self, Error> {
        lease.validate(coordinator.node_id(), SystemTime::now())?;
        if !store.entries.is_empty() {
            return Err(Error::ReplicatedStateCorrupt);
        }
        let records = coordinator.committed_records()?;
        let mut service = Self::new(issuer_certificate, signer, store, initial_crl_number);
        for record in records.iter().filter(|record| record.kind == "ocsp.status") {
            let mutation: OcspMutation = serde_json::from_slice(&record.payload)
                .map_err(|_| Error::ReplicatedStateCorrupt)?;
            let serial = SerialNumber::from_der(&mutation.serial_der)
                .map_err(|_| Error::ReplicatedStateCorrupt)?;
            match mutation.state {
                OcspMutationState::Good => service
                    .store
                    .get_mut()
                    .map_err(|_| Error::StoreUnavailable)?
                    .mark_good(&serial)?,
                OcspMutationState::Revoked {
                    at_unix_secs,
                    reason_code,
                } => {
                    let reason = reason_code
                        .map(reason_from_code)
                        .transpose()
                        .map_err(|_| Error::ReplicatedStateCorrupt)?;
                    let at = UNIX_EPOCH
                        .checked_add(Duration::from_secs(at_unix_secs))
                        .ok_or(Error::InvalidTime)?;
                    service
                        .store
                        .get_mut()
                        .map_err(|_| Error::StoreUnavailable)?
                        .revoke(&serial, at, reason)?;
                }
            }
            service
                .crl_number
                .fetch_max(mutation.crl_number, Ordering::SeqCst);
        }
        service.ha = Some(OcspHaContext {
            coordinator,
            lease: RwLock::new(lease),
        });
        Ok(service)
    }

    /// Renew the leader lease after the deployment's consensus system grants a newer fencing epoch.
    pub fn update_leadership_lease(&self, lease: LeadershipLease) -> Result<(), Error> {
        let ha = self.ha.as_ref().ok_or(Error::ReplicatedStateCorrupt)?;
        lease.validate(ha.coordinator.node_id(), SystemTime::now())?;
        let mut current = ha.lease.write().map_err(|_| Error::StoreUnavailable)?;
        if lease.term < current.term || lease.fencing_epoch < current.fencing_epoch {
            return Err(Error::Ha(HaError::NotLeader));
        }
        *current = lease;
        Ok(())
    }

    /// Mark a certificate known-good and advance the publication version.
    pub fn mark_good(&self, serial: &SerialNumber) -> Result<(), Error> {
        let mut store = self.store.write().map_err(|_| Error::StoreUnavailable)?;
        let next_crl_number = self
            .crl_number
            .load(Ordering::SeqCst)
            .checked_add(1)
            .ok_or(Error::InvalidTime)?;
        let mutation = OcspMutation {
            serial_der: serial.to_der()?,
            state: OcspMutationState::Good,
            crl_number: next_crl_number,
        };
        let reconciliation_needed = self.commit_mutation(&mutation)?;
        store.mark_good(serial)?;
        self.crl_number.store(next_crl_number, Ordering::SeqCst);
        if reconciliation_needed {
            return Err(Error::Ha(HaError::CommitNeedsReconciliation));
        }
        Ok(())
    }

    /// Revoke a certificate and advance the publication version.
    pub fn revoke(
        &self,
        serial: &SerialNumber,
        at: SystemTime,
        reason: Option<x509_cert::ext::pkix::crl::CrlReason>,
    ) -> Result<(), Error> {
        let mut store = self.store.write().map_err(|_| Error::StoreUnavailable)?;
        let at_unix_secs = at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidTime)?
            .as_secs();
        let next_crl_number = self
            .crl_number
            .load(Ordering::SeqCst)
            .checked_add(1)
            .ok_or(Error::InvalidTime)?;
        let mutation = OcspMutation {
            serial_der: serial.to_der()?,
            state: OcspMutationState::Revoked {
                at_unix_secs,
                reason_code: reason.map(|value| value as u32),
            },
            crl_number: next_crl_number,
        };
        let reconciliation_needed = self.commit_mutation(&mutation)?;
        store.revoke(serial, at, reason)?;
        self.crl_number.store(next_crl_number, Ordering::SeqCst);
        if reconciliation_needed {
            return Err(Error::Ha(HaError::CommitNeedsReconciliation));
        }
        Ok(())
    }

    fn commit_mutation(&self, mutation: &OcspMutation) -> Result<bool, Error> {
        if let Some(ha) = &self.ha {
            let payload =
                serde_json::to_vec(mutation).map_err(|_| Error::ReplicatedStateCorrupt)?;
            let lease = ha
                .lease
                .read()
                .map_err(|_| Error::StoreUnavailable)?
                .clone();
            match ha.coordinator.commit(&lease, "ocsp.status", &payload) {
                Ok(_) => return Ok(false),
                Err(HaError::CommitNeedsReconciliation) => return Ok(true),
                Err(error) => return Err(Error::Ha(error)),
            }
        }
        Ok(false)
    }

    /// Respond to a DER OCSP request for this tenant.
    pub fn respond(&self, request_der: &[u8]) -> Result<Vec<u8>, Error> {
        let store = self.store.read().map_err(|_| Error::StoreUnavailable)?;
        respond_ml_dsa65(request_der, &self.issuer_certificate, &self.signer, &store)
    }

    /// Generate the current signed CRL for this tenant.
    pub fn current_crl(&self) -> Result<Vec<u8>, Error> {
        let store = self.store.read().map_err(|_| Error::StoreUnavailable)?;
        build_ml_dsa65_crl(
            self.issuer_certificate.tbs_certificate().subject(),
            &self.signer,
            &store,
            self.crl_number.load(Ordering::SeqCst),
        )
    }

    /// Issuer certificate associated with this responder.
    pub fn issuer_certificate(&self) -> &Certificate {
        &self.issuer_certificate
    }

    /// HA coordinator when this responder is configured for replicated state.
    pub fn ha_coordinator(&self) -> Option<&Arc<HaCoordinator>> {
        self.ha.as_ref().map(|ha| &ha.coordinator)
    }
    /// Tenant journal namespace when this responder is HA-enabled.
    pub fn ha_tenant_id(&self) -> Option<&nexusq_ha::TenantId> {
        self.ha.as_ref().map(|ha| ha.coordinator.tenant())
    }

    /// Return an Axum router exposing OCSP and CRL endpoints.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/ocsp", post(ocsp_handler))
            .route("/crl", get(crl_handler))
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
            .with_state(self)
    }
}

async fn ocsp_handler(State(service): State<Arc<OcspService>>, body: Bytes) -> impl IntoResponse {
    match service.respond(&body) {
        Ok(response) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/ocsp-response")],
            response,
        ),
        Err(
            Error::Der(_)
            | Error::InvalidRequestSize
            | Error::UnsupportedHashAlgorithm
            | Error::IssuerMismatch
            | Error::UnsupportedRequestFeatures,
        ) => (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain")],
            b"invalid OCSP request".to_vec(),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain")],
            b"OCSP response failed".to_vec(),
        ),
    }
}

async fn crl_handler(State(service): State<Arc<OcspService>>) -> impl IntoResponse {
    match service.current_crl() {
        Ok(crl) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/pkix-crl")],
            crl,
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain")],
            b"CRL generation failed".to_vec(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Generate, Keypair, Verifier};
    use std::str::FromStr;
    use x509_cert::name::Name;
    use x509_cert::{
        builder::{Builder, CertificateBuilder, profile::cabf},
        spki::SubjectPublicKeyInfoOwned,
        time::Validity,
    };

    fn fixture() -> (SigningKey<MlDsa65>, Certificate) {
        let key = SigningKey::<MlDsa65>::generate();
        let subject = Name::from_str("CN=NexusQ OCSP Test,O=NexusQ,C=US").unwrap();
        let profile = cabf::Root::new(false, subject).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_key(&key.verifying_key()).unwrap();
        let builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(3600 * 24)).unwrap(),
            spki,
        )
        .unwrap();
        let cert = builder
            .build::<SigningKey<MlDsa65>, ml_dsa::Signature<MlDsa65>>(&key)
            .unwrap();
        (key, cert)
    }

    fn request_item_for(issuer: &Certificate, serial: SerialNumber) -> RequestItem {
        let cert_id = CertId {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.3.14.3.2.26"),
                parameters: Some(Null.into()),
            },
            issuer_name_hash: OctetString::new(
                Sha1::digest(issuer.tbs_certificate().subject().to_der().unwrap()).to_vec(),
            )
            .unwrap(),
            issuer_key_hash: OctetString::new(
                Sha1::digest(
                    issuer
                        .tbs_certificate()
                        .subject_public_key_info()
                        .subject_public_key
                        .raw_bytes(),
                )
                .to_vec(),
            )
            .unwrap(),
            serial_number: serial,
        };
        RequestItem {
            req_cert: cert_id,
            single_request_extensions: None,
        }
    }

    fn request_for(issuer: &Certificate, serial: SerialNumber) -> Vec<u8> {
        OcspRequest {
            tbs_request: TbsRequest {
                version: None,
                requestor_name: None,
                request_list: vec![request_item_for(issuer, serial)],
                request_extensions: None,
            },
            optional_signature: None,
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn ha_ocsp_replays_revocation_state_and_crl_number_after_restart() {
        use nexusq_ha::{DurableTenantJournal, HaCoordinator, LeadershipLease, TenantId};
        let dir = tempfile::tempdir().unwrap();
        let (key, issuer) = fixture();
        let journal = Arc::new(
            DurableTenantJournal::open(dir.path(), TenantId::new("tenant-a").unwrap()).unwrap(),
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
        let good_serial = SerialNumber::from(41u32);
        let revoked_serial = SerialNumber::from(42u32);
        let service = OcspService::new_ha(
            issuer.clone(),
            key.clone(),
            RevocationStore::new(),
            7,
            coordinator.clone(),
            lease.clone(),
        )
        .unwrap();
        service.mark_good(&good_serial).unwrap();
        service
            .revoke(
                &revoked_serial,
                SystemTime::now(),
                Some(x509_cert::ext::pkix::crl::CrlReason::KeyCompromise),
            )
            .unwrap();
        assert_eq!(service.crl_number.load(Ordering::SeqCst), 9);
        drop(service);
        let restored =
            OcspService::new_ha(issuer, key, RevocationStore::new(), 7, coordinator, lease)
                .unwrap();
        assert!(matches!(
            restored.store.read().unwrap().get(&good_serial).unwrap(),
            Some(CertificateStatus::Good)
        ));
        assert!(matches!(
            restored.store.read().unwrap().get(&revoked_serial).unwrap(),
            Some(CertificateStatus::Revoked {
                reason: Some(x509_cert::ext::pkix::crl::CrlReason::KeyCompromise),
                ..
            })
        ));
        assert_eq!(restored.crl_number.load(Ordering::SeqCst), 9);
    }

    #[test]
    fn emits_signed_ocsp_unknown_for_unregistered_serial() {
        let (key, issuer) = fixture();
        let request = request_for(&issuer, SerialNumber::from(55u32));
        let response_der =
            respond_ml_dsa65(&request, &issuer, &key, &RevocationStore::new()).unwrap();
        if let Ok(dir) = std::env::var("NEXUSQ_OCSP_TEST_OUTPUT_DIR") {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                std::path::Path::new(&dir).join("response.der"),
                &response_der,
            )
            .unwrap();
        }
        let response = OcspResponse::from_der(&response_der).unwrap();
        assert_eq!(response.response_status, ResponseStatus::Successful);
        let bytes = response.response_bytes.unwrap();
        assert_eq!(bytes.response_type, ID_PKIX_OCSP_BASIC);
        let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).unwrap();
        assert!(matches!(
            basic.tbs_response_data.responses[0].cert_status,
            CertStatus::Unknown(_)
        ));
        let tbs = basic.tbs_response_data.to_der().unwrap();
        let signature =
            ml_dsa::Signature::<MlDsa65>::try_from(basic.signature.as_bytes().unwrap()).unwrap();
        key.verifying_key().verify(&tbs, &signature).unwrap();
    }

    #[test]
    fn known_good_and_revoked_states_are_distinct() {
        let (key, issuer) = fixture();
        let good_serial = SerialNumber::from(77u32);
        let revoked_serial = SerialNumber::from(78u32);
        let mut store = RevocationStore::new();
        store.mark_good(&good_serial).unwrap();
        store
            .revoke(
                &revoked_serial,
                SystemTime::now(),
                Some(x509_cert::ext::pkix::crl::CrlReason::KeyCompromise),
            )
            .unwrap();
        assert!(matches!(
            store.get(&good_serial).unwrap(),
            Some(CertificateStatus::Good)
        ));
        assert!(matches!(
            store.get(&revoked_serial).unwrap(),
            Some(CertificateStatus::Revoked { .. })
        ));
        let crl_der =
            build_ml_dsa65_crl(issuer.tbs_certificate().subject(), &key, &store, 1).unwrap();
        let crl = CertificateList::<x509_cert::certificate::Rfc5280>::from_der(&crl_der).unwrap();
        assert_eq!(
            crl.tbs_cert_list
                .revoked_certificates
                .as_ref()
                .unwrap()
                .len(),
            1
        );
        assert!(crl.tbs_cert_list.crl_extensions.is_some());
        let tbs = crl.tbs_cert_list.to_der().unwrap();
        let signature =
            ml_dsa::Signature::<MlDsa65>::try_from(crl.signature.as_bytes().unwrap()).unwrap();
        key.verifying_key().verify(&tbs, &signature).unwrap();
    }

    #[test]
    fn returns_good_revoked_and_unknown_statuses_in_one_response() {
        let (key, issuer) = fixture();
        let good_serial = SerialNumber::from(77u32);
        let revoked_serial = SerialNumber::from(78u32);
        let unknown_serial = SerialNumber::from(79u32);
        let mut store = RevocationStore::new();
        store.mark_good(&good_serial).unwrap();
        store
            .revoke(
                &revoked_serial,
                SystemTime::now(),
                Some(x509_cert::ext::pkix::crl::CrlReason::KeyCompromise),
            )
            .unwrap();
        let request = OcspRequest {
            tbs_request: TbsRequest {
                version: None,
                requestor_name: None,
                request_list: vec![
                    request_item_for(&issuer, good_serial),
                    request_item_for(&issuer, revoked_serial),
                    request_item_for(&issuer, unknown_serial),
                ],
                request_extensions: None,
            },
            optional_signature: None,
        }
        .to_der()
        .unwrap();
        let response = respond_ml_dsa65(&request, &issuer, &key, &store).unwrap();
        let envelope = OcspResponse::from_der(&response).unwrap();
        let basic =
            BasicOcspResponse::from_der(envelope.response_bytes.unwrap().response.as_bytes())
                .unwrap();
        assert!(matches!(
            basic.tbs_response_data.responses[0].cert_status,
            CertStatus::Good(_)
        ));
        assert!(matches!(
            basic.tbs_response_data.responses[1].cert_status,
            CertStatus::Revoked(_)
        ));
        assert!(matches!(
            basic.tbs_response_data.responses[2].cert_status,
            CertStatus::Unknown(_)
        ));
    }

    #[tokio::test]
    async fn http_router_serves_ocsp_and_crl_content_types() {
        use axum::{body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let (key, issuer) = fixture();
        let service = Arc::new(OcspService::new(
            issuer.clone(),
            key,
            RevocationStore::new(),
            1,
        ));
        let app = service.router();
        let request_body = request_for(&issuer, SerialNumber::from(81u32));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ocsp")
                    .header(header::CONTENT_TYPE, "application/ocsp-request")
                    .body(Body::from(request_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/ocsp-response"
        );
        assert!(
            validate_response_envelope(&response.into_body().collect().await.unwrap().to_bytes())
                .is_ok()
        );
        let response = app
            .oneshot(Request::builder().uri("/crl").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/pkix-crl"
        );
        assert!(
            !response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }

    #[test]
    fn rejects_request_with_wrong_issuer_hash() {
        let (key, issuer) = fixture();
        let mut request: OcspRequest =
            OcspRequest::from_der(&request_for(&issuer, SerialNumber::from(5u32))).unwrap();
        request.tbs_request.request_list[0].req_cert.issuer_key_hash =
            OctetString::new(vec![0u8; 20]).unwrap();
        assert!(matches!(
            respond_ml_dsa65(
                &request.to_der().unwrap(),
                &issuer,
                &key,
                &RevocationStore::new()
            ),
            Err(Error::IssuerMismatch)
        ));
    }
}

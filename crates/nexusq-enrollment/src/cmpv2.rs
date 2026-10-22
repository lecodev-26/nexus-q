//! CMPv2 P10CR enrollment with password-based message protection (RFC 4210).

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use const_oid::ObjectIdentifier;
use der::{
    Choice, Decode, Encode, Enumerated, Sequence,
    asn1::{Any, BitString, GeneralizedTime, Int, OctetString},
};
use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use subtle::ConstantTimeEq;
use x509_cert::{Certificate, ext::pkix::name::GeneralName, name::Name, request::CertReq};

use crate::{EnrollmentAuthority, Error as EnrollmentError, Principal, Protocol};

const MAX_CMP_BYTES: usize = 1024 * 1024;
const MIN_PBM_ITERATIONS: u64 = 1000;
const MAX_PBM_ITERATIONS: u64 = 10_000;
const ID_PASSWORD_BASED_MAC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113533.7.66.13");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_HMAC_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
enum CmpVersion {
    Cmp2000 = 2,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct PbmParameter {
    salt: OctetString,
    owf: AlgorithmIdentifierOwned,
    iteration_count: u64,
    mac: AlgorithmIdentifierOwned,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct PkiHeader {
    pvno: CmpVersion,
    sender: GeneralName,
    recipient: GeneralName,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    message_time: Option<GeneralizedTime>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    protection_alg: Option<AlgorithmIdentifierOwned>,
    #[asn1(
        context_specific = "2",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    sender_kid: Option<OctetString>,
    #[asn1(
        context_specific = "3",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    recip_kid: Option<OctetString>,
    #[asn1(
        context_specific = "4",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    transaction_id: Option<OctetString>,
    #[asn1(
        context_specific = "5",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    sender_nonce: Option<OctetString>,
    #[asn1(
        context_specific = "6",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    recip_nonce: Option<OctetString>,
    #[asn1(
        context_specific = "7",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    free_text: Option<Any>,
    #[asn1(
        context_specific = "8",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    general_info: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
enum RequestBody {
    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", constructed = "true")]
    P10cr(CertReq),
}
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
enum ResponseBody {
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
    Cp(CertRepMessage),
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct RequestMessage {
    header: PkiHeader,
    body: RequestBody,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    protection: Option<BitString>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    extra_certs: Option<Vec<Certificate>>,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ResponseMessage {
    header: PkiHeader,
    body: ResponseBody,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "false",
        optional = "true"
    )]
    protection: Option<BitString>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    extra_certs: Option<Vec<Certificate>>,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ProtectedRequestPart {
    header: PkiHeader,
    body: RequestBody,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ProtectedResponsePart {
    header: PkiHeader,
    body: ResponseBody,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct CertRepMessage {
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    ca_pubs: Option<Vec<Certificate>>,
    response: Vec<CertResponse>,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct CertResponse {
    cert_req_id: Int,
    status: PkiStatusInfo,
    certified_key_pair: Option<CertifiedKeyPair>,
    rsp_info: Option<OctetString>,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct PkiStatusInfo {
    status: Int,
    status_string: Option<Any>,
    fail_info: Option<BitString>,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct CertifiedKeyPair {
    cert_or_enc_cert: CertOrEncCert,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    private_key: Option<Any>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    publication_info: Option<Any>,
}
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
enum CertOrEncCert {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
    Certificate(Box<Certificate>),
}

/// Shared-secret identities for CMP PBM authentication. Secrets must contain at least 128 bits.
pub struct CmpCredentials {
    users: HashMap<String, Vec<u8>>,
}
impl CmpCredentials {
    /// Build credentials from stable senderKID identifiers and shared secrets.
    pub fn new<I, U, S>(credentials: I) -> Result<Self, EnrollmentError>
    where
        I: IntoIterator<Item = (U, S)>,
        U: Into<String>,
        S: Into<Vec<u8>>,
    {
        let mut users = HashMap::new();
        for (id, secret) in credentials {
            let id = id.into();
            let secret = secret.into();
            if id.is_empty() || secret.len() < 16 || users.insert(id, secret).is_some() {
                return Err(EnrollmentError::InvalidPolicy);
            }
        }
        if users.is_empty() {
            return Err(EnrollmentError::InvalidPolicy);
        }
        Ok(Self { users })
    }
    fn secret(&self, id: &str) -> Option<&[u8]> {
        self.users.get(id).map(Vec::as_slice)
    }
}

impl EnrollmentAuthority {
    /// Mount the CMPv2 P10CR endpoint at `/cmp`, authenticated with PBM/HMAC-SHA-256.
    /// CRMF `ir`/`cr` requests and non-PBM message protection are rejected rather than downgraded.
    pub fn cmp_router(self: Arc<Self>, credentials: CmpCredentials) -> Router {
        Router::new()
            .route("/cmp", post(cmp_handler))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_CMP_BYTES))
            .with_state(CmpState {
                authority: self,
                credentials: Arc::new(credentials),
                replay: Arc::new(Mutex::new(HashMap::new())),
            })
    }
}

#[derive(Clone)]
struct CmpState {
    authority: Arc<EnrollmentAuthority>,
    credentials: Arc<CmpCredentials>,
    replay: Arc<Mutex<HashMap<String, Instant>>>,
}

async fn cmp_handler(State(state): State<CmpState>, body: Bytes) -> impl IntoResponse {
    if body.is_empty() || body.len() > MAX_CMP_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain")],
            "invalid CMP message",
        )
            .into_response();
    }
    match handle_cmp(&state, &body) {
        Ok(response) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/pkixcmp")],
            response,
        )
            .into_response(),
        Err(CmpError::Authentication) => (
            StatusCode::UNAUTHORIZED,
            [(header::CONTENT_TYPE, "text/plain")],
            "CMP protection validation failed",
        )
            .into_response(),
        Err(CmpError::Enrollment(EnrollmentError::RateLimited)) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::CONTENT_TYPE, "text/plain")],
            "enrollment rate limit exceeded",
        )
            .into_response(),
        Err(CmpError::Enrollment(
            EnrollmentError::StateUnavailable
            | EnrollmentError::Ha(_)
            | EnrollmentError::Issuance(_)
            | EnrollmentError::Signing(_)
            | EnrollmentError::ExternalSigning(_),
        )) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain")],
            "CMP enrollment failed",
        )
            .into_response(),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain")],
            "CMP request rejected by policy",
        )
            .into_response(),
    }
}

#[derive(Debug)]
enum CmpError {
    Der,
    Authentication,
    Unsupported,
    Enrollment(EnrollmentError),
    Crypto,
}
impl From<der::Error> for CmpError {
    fn from(_value: der::Error) -> Self {
        Self::Der
    }
}
impl From<EnrollmentError> for CmpError {
    fn from(value: EnrollmentError) -> Self {
        Self::Enrollment(value)
    }
}

fn algorithm(oid: ObjectIdentifier, parameters: Option<Any>) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid, parameters }
}
fn pbm_algorithm(params: &PbmParameter) -> Result<AlgorithmIdentifierOwned, CmpError> {
    Ok(algorithm(
        ID_PASSWORD_BASED_MAC,
        Some(Any::encode_from(params)?),
    ))
}
fn new_pbm_parameters() -> Result<PbmParameter, CmpError> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|_| CmpError::Crypto)?;
    Ok(PbmParameter {
        salt: OctetString::new(salt)?,
        owf: algorithm(ID_SHA256, None),
        iteration_count: MIN_PBM_ITERATIONS,
        mac: algorithm(ID_HMAC_SHA256, None),
    })
}
fn derive_mac(
    secret: &[u8],
    params: &PbmParameter,
    protected_part: &[u8],
) -> Result<Vec<u8>, CmpError> {
    if params.iteration_count < MIN_PBM_ITERATIONS
        || params.iteration_count > MAX_PBM_ITERATIONS
        || params.salt.as_bytes().len() < 16
        || params.salt.as_bytes().len() > 64
        || params.owf.oid != ID_SHA256
        || params.mac.oid != ID_HMAC_SHA256
    {
        return Err(CmpError::Unsupported);
    }
    let mut input = Vec::with_capacity(secret.len() + params.salt.as_bytes().len());
    input.extend_from_slice(secret);
    input.extend_from_slice(params.salt.as_bytes());
    let mut key = Sha256::digest(&input).to_vec();
    for _ in 1..params.iteration_count {
        key = Sha256::digest(&key).to_vec();
    }
    let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| CmpError::Crypto)?;
    mac.update(protected_part);
    Ok(mac.finalize().into_bytes().to_vec())
}
fn verify_protection(message: &RequestMessage, secret: &[u8]) -> Result<PbmParameter, CmpError> {
    let algorithm = message
        .header
        .protection_alg
        .as_ref()
        .ok_or(CmpError::Authentication)?;
    if algorithm.oid != ID_PASSWORD_BASED_MAC {
        return Err(CmpError::Unsupported);
    }
    let params = algorithm
        .parameters
        .as_ref()
        .ok_or(CmpError::Authentication)?
        .decode_as::<PbmParameter>()?;
    let protected = ProtectedRequestPart {
        header: message.header.clone(),
        body: message.body.clone(),
    }
    .to_der()?;
    let expected = derive_mac(secret, &params, &protected)?;
    let actual = message
        .protection
        .as_ref()
        .and_then(BitString::as_bytes)
        .ok_or(CmpError::Authentication)?;
    if !bool::from(expected.as_slice().ct_eq(actual)) {
        return Err(CmpError::Authentication);
    }
    Ok(params)
}
fn handle_cmp(state: &CmpState, body: &[u8]) -> Result<Vec<u8>, CmpError> {
    let request = RequestMessage::from_der(body)?;
    if request.header.pvno != CmpVersion::Cmp2000
        || request
            .header
            .transaction_id
            .as_ref()
            .is_none_or(|id| id.as_bytes().len() < 16)
        || request
            .header
            .sender_nonce
            .as_ref()
            .is_none_or(|nonce| nonce.as_bytes().len() < 16)
    {
        return Err(CmpError::Unsupported);
    }
    let expected_recipient = GeneralName::DirectoryName(
        state
            .authority
            .issuer_certificate()
            .tbs_certificate()
            .subject()
            .clone(),
    );
    if request.header.recipient.to_der()? != expected_recipient.to_der()? {
        return Err(CmpError::Unsupported);
    }
    let sender_kid = request
        .header
        .sender_kid
        .as_ref()
        .ok_or(CmpError::Authentication)?;
    let principal_id =
        std::str::from_utf8(sender_kid.as_bytes()).map_err(|_| CmpError::Authentication)?;
    let expected_sender = GeneralName::DirectoryName(
        Name::from_str(&format!("CN={principal_id}")).map_err(|_| CmpError::Authentication)?,
    );
    if request.header.sender.to_der()? != expected_sender.to_der()? {
        return Err(CmpError::Authentication);
    }
    let secret = state
        .credentials
        .secret(principal_id)
        .ok_or(CmpError::Authentication)?;
    let _request_pbm = verify_protection(&request, secret)?;
    let message_time = request
        .header
        .message_time
        .as_ref()
        .ok_or(CmpError::Unsupported)?
        .to_system_time();
    let now = SystemTime::now();
    let age = now
        .duration_since(message_time)
        .or_else(|_| message_time.duration_since(now))
        .map_err(|_| CmpError::Unsupported)?;
    if age > Duration::from_secs(300) {
        return Err(CmpError::Authentication);
    }
    let transaction_id = request
        .header
        .transaction_id
        .as_ref()
        .ok_or(CmpError::Unsupported)?;
    let sender_nonce = request
        .header
        .sender_nonce
        .as_ref()
        .ok_or(CmpError::Unsupported)?;
    let replay_key = format!(
        "{}:{}:{}",
        principal_id,
        STANDARD.encode(transaction_id.as_bytes()),
        STANDARD.encode(sender_nonce.as_bytes())
    );
    {
        let mut replay = state.replay.lock().map_err(|_| CmpError::Crypto)?;
        replay.retain(|_, seen| seen.elapsed() <= Duration::from_secs(300));
        if replay.contains_key(&replay_key) {
            return Err(CmpError::Authentication);
        }
        if replay.len() >= 10_000
            && let Some(oldest) = replay
                .iter()
                .min_by_key(|(_, seen)| *seen)
                .map(|(key, _)| key.clone())
        {
            replay.remove(&oldest);
        }
        replay.insert(replay_key, Instant::now());
    }
    let RequestBody::P10cr(csr) = request.body;
    let cert = state.authority.enroll_csr(
        &Principal {
            id: principal_id.to_owned(),
        },
        Protocol::Cmpv2,
        &csr.to_der()?,
    )?;
    let mut sender_nonce = [0u8; 32];
    getrandom::fill(&mut sender_nonce).map_err(|_| CmpError::Crypto)?;
    let response_pbm = new_pbm_parameters()?;
    let response_header = PkiHeader {
        pvno: CmpVersion::Cmp2000,
        sender: GeneralName::DirectoryName(
            state
                .authority
                .issuer_certificate()
                .tbs_certificate()
                .subject()
                .clone(),
        ),
        recipient: request.header.sender.clone(),
        message_time: Some(
            GeneralizedTime::from_system_time(SystemTime::now()).map_err(|_| CmpError::Crypto)?,
        ),
        protection_alg: Some(pbm_algorithm(&response_pbm)?),
        sender_kid: Some(OctetString::new(b"nexusq-ca".to_vec())?),
        recip_kid: request.header.sender_kid.clone(),
        transaction_id: request.header.transaction_id.clone(),
        sender_nonce: Some(OctetString::new(sender_nonce)?),
        recip_nonce: request.header.sender_nonce.clone(),
        free_text: None,
        general_info: None,
    };
    let response_body = ResponseBody::Cp(CertRepMessage {
        ca_pubs: Some(vec![state.authority.issuer_certificate().clone()]),
        response: vec![CertResponse {
            cert_req_id: Int::try_from(-1i32)?,
            status: PkiStatusInfo {
                status: Int::try_from(0i32)?,
                status_string: None,
                fail_info: None,
            },
            certified_key_pair: Some(CertifiedKeyPair {
                cert_or_enc_cert: CertOrEncCert::Certificate(Box::new(cert)),
                private_key: None,
                publication_info: None,
            }),
            rsp_info: None,
        }],
    });
    let protected_part = ProtectedResponsePart {
        header: response_header.clone(),
        body: response_body.clone(),
    }
    .to_der()?;
    let response_mac = derive_mac(secret, &response_pbm, &protected_part)?;
    let response = ResponseMessage {
        header: response_header,
        body: response_body,
        protection: Some(BitString::from_bytes(&response_mac)?),
        extra_certs: None,
    };
    Ok(response.to_der()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use der::{Encode, asn1::Ia5String};
    use http_body_util::BodyExt;
    use ml_dsa::{Generate, Keypair, MlDsa65, Signature as MlDsaSignature, SigningKey};
    use std::{str::FromStr, time::Duration};
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

    fn fixture() -> (Arc<EnrollmentAuthority>, Vec<u8>, SigningKey<MlDsa65>) {
        let ca_key = SigningKey::<MlDsa65>::generate();
        let ca_name = Name::from_str("CN=NexusQ CMP Test Root,O=NexusQ,C=US").unwrap();
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
        let authority = Arc::new(
            EnrollmentAuthority::new(
                ca_cert,
                ca_key,
                crate::EnrollmentPolicy::new(vec!["example.com".into()]).unwrap(),
                100,
            )
            .unwrap(),
        );
        let csr_key = SigningKey::<MlDsa65>::generate();
        let subject = Name::from_str("CN=cmp.example.com").unwrap();
        let mut request = RequestBuilder::new(subject).unwrap();
        request
            .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
                Ia5String::new("cmp.example.com").unwrap(),
            )]))
            .unwrap();
        let csr = request
            .build::<SigningKey<MlDsa65>, MlDsaSignature<MlDsa65>>(&csr_key)
            .unwrap();
        (authority, csr.to_der().unwrap(), csr_key)
    }

    #[tokio::test]
    async fn cmp_p10cr_requires_pbm_and_returns_protected_certificate_response() {
        let (authority, csr, _) = fixture();
        let secret = b"test-shared-secret-32-bytes-long".to_vec();
        let credentials = CmpCredentials::new([("device-cmp", secret.clone())]).unwrap();
        let app = authority.clone().cmp_router(credentials);
        let params = PbmParameter {
            salt: OctetString::new([7u8; 32]).unwrap(),
            owf: algorithm(ID_SHA256, None),
            iteration_count: MIN_PBM_ITERATIONS,
            mac: algorithm(ID_HMAC_SHA256, None),
        };
        let header = PkiHeader {
            pvno: CmpVersion::Cmp2000,
            sender: GeneralName::DirectoryName(Name::from_str("CN=device-cmp").unwrap()),
            recipient: GeneralName::DirectoryName(
                authority
                    .issuer_certificate()
                    .tbs_certificate()
                    .subject()
                    .clone(),
            ),
            message_time: Some(GeneralizedTime::from_system_time(SystemTime::now()).unwrap()),
            protection_alg: Some(pbm_algorithm(&params).unwrap()),
            sender_kid: Some(OctetString::new(b"device-cmp".to_vec()).unwrap()),
            recip_kid: None,
            transaction_id: Some(OctetString::new([3u8; 16]).unwrap()),
            sender_nonce: Some(OctetString::new([4u8; 16]).unwrap()),
            recip_nonce: None,
            free_text: None,
            general_info: None,
        };
        let body = RequestBody::P10cr(CertReq::from_der(&csr).unwrap());
        let protected = ProtectedRequestPart {
            header: header.clone(),
            body: body.clone(),
        }
        .to_der()
        .unwrap();
        let mac = derive_mac(&secret, &params, &protected).unwrap();
        let request = RequestMessage {
            header,
            body,
            protection: Some(BitString::from_bytes(&mac).unwrap()),
            extra_certs: None,
        }
        .to_der()
        .unwrap();
        let replay_request = request.clone();
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/cmp")
                    .header(header::CONTENT_TYPE, "application/pkixcmp")
                    .body(Body::from(request))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/pkixcmp"
        );
        let response_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response = ResponseMessage::from_der(&response_bytes).unwrap();
        let params = response
            .header
            .protection_alg
            .as_ref()
            .unwrap()
            .parameters
            .as_ref()
            .unwrap()
            .decode_as::<PbmParameter>()
            .unwrap();
        let protected = ProtectedResponsePart {
            header: response.header.clone(),
            body: response.body.clone(),
        }
        .to_der()
        .unwrap();
        let expected = derive_mac(&secret, &params, &protected).unwrap();
        assert!(bool::from(expected.as_slice().ct_eq(
            response.protection.as_ref().unwrap().as_bytes().unwrap()
        )));
        let ResponseBody::Cp(rep) = response.body;
        assert_eq!(rep.response.len(), 1);
        assert!(rep.response[0].certified_key_pair.is_some());
        let replay = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/cmp")
                    .header(header::CONTENT_TYPE, "application/pkixcmp")
                    .body(Body::from(replay_request))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }
}

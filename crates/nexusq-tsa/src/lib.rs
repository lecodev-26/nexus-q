//! RFC 3161 Time-Stamp Authority (TSA) with ML-DSA-65 CMS signatures.
//!
//! The caller supplies a dedicated TSA certificate and its ML-DSA-65 signing key. The certificate
//! must be a valid TSA certificate with the critical `id-kp-timeStamping` EKU and a public key that
//! matches the supplied key. This crate checks the certificate/key match and EKU before issuing.
//! Time is injected through `TimeSource` so deployments can use an audited, synchronized source.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use const_oid::ObjectIdentifier;
use der::{
    Decode, Encode, Sequence,
    asn1::{Any, GeneralizedTime, OctetString, SetOfVec, Uint},
};
use ml_dsa::{MlDsa65, Signature as MlDsaSignature, SigningKey};
use sha2::{Digest, Sha256};
use signature::Keypair;
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    Certificate,
    attr::Attribute,
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
};

const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const TST_INFO_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const CONTENT_TYPE_ATTR_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const SIGNING_CERT_V2_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const TIMESTAMPING_EKU_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const MAX_REQUEST_SIZE: usize = 64 * 1024;

/// RFC 3161 MessageImprint.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct MessageImprint {
    /// Digest algorithm identifier.
    pub hash_algorithm: AlgorithmIdentifierOwned,
    /// Hash of the data being timestamped.
    pub hashed_message: OctetString,
}

/// RFC 3161 TimeStampReq. Unsupported algorithms and malformed requests are rejected.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampRequest {
    /// Must be 1 for RFC 3161.
    pub version: Uint,
    /// Imprint of the data being timestamped.
    pub message_imprint: MessageImprint,
    /// Optional requested TSA policy.
    pub req_policy: Option<ObjectIdentifier>,
    /// Optional nonce echoed unchanged in the token.
    pub nonce: Option<Uint>,
    /// Whether the token should carry the TSA certificate. The implementation always includes it.
    #[asn1(default = "default_false")]
    pub cert_req: bool,
    /// Optional request extensions; unknown critical extensions are rejected by this implementation.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Vec<Extension>>,
}
fn default_false() -> bool {
    false
}

/// RFC 3161 Extension.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Extension {
    /// Extension identifier.
    pub extn_id: ObjectIdentifier,
    /// Critical flag, default false.
    #[asn1(default = "default_false")]
    pub critical: bool,
    /// DER-encoded extension value.
    pub extn_value: OctetString,
}

/// RFC 3161 TSTInfo structure embedded in the CMS token.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TstInfo {
    /// Must be 1.
    pub version: Uint,
    /// TSA policy OID.
    pub policy: ObjectIdentifier,
    /// Echoed and validated message imprint.
    pub message_imprint: MessageImprint,
    /// Monotonically increasing serial number.
    pub serial_number: Uint,
    /// Time assigned by the configured time source.
    pub gen_time: GeneralizedTime,
    /// Optional accuracy; omitted when the source does not provide a defensible bound.
    pub accuracy: Option<Accuracy>,
    /// Ordering is omitted (default false).
    #[asn1(default = "default_false")]
    pub ordering: bool,
    /// Optional nonce copied from the request.
    pub nonce: Option<Uint>,
}

/// RFC 3161 accuracy in seconds/milliseconds/microseconds.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Accuracy {
    /// Whole seconds of uncertainty.
    pub seconds: Option<Uint>,
    /// Milliseconds, 1..999.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub millis: Option<Uint>,
    /// Microseconds, 1..999.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub micros: Option<Uint>,
}

/// Injectable trusted time source. Implementations should enforce synchronization and alerting.
pub trait TimeSource: Send + Sync {
    /// Return current UTC time.
    fn now(&self) -> Result<SystemTime, String>;
}

/// System clock adapter. Production services should use an audited synchronized source.
pub struct SystemTimeSource;
impl TimeSource for SystemTimeSource {
    fn now(&self) -> Result<SystemTime, String> {
        Ok(SystemTime::now())
    }
}

/// Errors while parsing a request or creating a timestamp token.
#[derive(Debug, thiserror::Error)]
pub enum TsaError {
    /// Invalid DER request.
    #[error("invalid RFC 3161 request DER")]
    InvalidRequest,
    /// Unsupported digest algorithm or invalid imprint length.
    #[error("unsupported or malformed message imprint")]
    InvalidImprint,
    /// Request asked for a policy this TSA does not serve.
    #[error("requested timestamp policy is not supported")]
    UnsupportedPolicy,
    /// The configured TSA certificate does not satisfy RFC 3161 requirements.
    #[error("invalid TSA signing certificate: {0}")]
    InvalidCertificate(&'static str),
    /// Configured signing key does not match the TSA certificate.
    #[error("TSA signing key does not match its certificate")]
    KeyMismatch,
    /// Trusted time source failed or returned an implausible time.
    #[error("trusted time source failed")]
    TimeSource,
    /// ASN.1 or CMS construction failed.
    #[error("ASN.1/CMS encoding failed: {0}")]
    Der(#[from] der::Error),
    /// CMS construction failed.
    #[error("CMS token construction failed")]
    Cms,
}

/// RFC 3161 timestamp authority. Serial allocation is process-local; HA deployments must replace
/// this allocator with a durable, transactional monotonic allocator before clustering.
pub struct TimestampAuthority<K = SystemTimeSource> {
    policy: ObjectIdentifier,
    certificate: Certificate,
    signing_key: SigningKey<MlDsa65>,
    time_source: K,
    serial: AtomicU64,
    last_time: std::sync::Mutex<Option<SystemTime>>,
}

impl TimestampAuthority<SystemTimeSource> {
    /// Create a TSA using the operating-system clock. For production, prefer `with_time_source`.
    pub fn new(
        policy: ObjectIdentifier,
        certificate: Certificate,
        signing_key: SigningKey<MlDsa65>,
        first_serial: u64,
    ) -> Result<Self, TsaError> {
        Self::with_time_source(
            policy,
            certificate,
            signing_key,
            first_serial,
            SystemTimeSource,
        )
    }
}

impl<K: TimeSource> TimestampAuthority<K> {
    /// Create a TSA with an explicit trusted time source and first serial number.
    pub fn with_time_source(
        policy: ObjectIdentifier,
        certificate: Certificate,
        signing_key: SigningKey<MlDsa65>,
        first_serial: u64,
        time_source: K,
    ) -> Result<Self, TsaError> {
        if first_serial == 0 {
            return Err(TsaError::InvalidRequest);
        }
        validate_tsa_certificate(&certificate, &signing_key)?;
        Ok(Self {
            policy,
            certificate,
            signing_key,
            time_source,
            serial: AtomicU64::new(first_serial),
            last_time: std::sync::Mutex::new(None),
        })
    }

    /// Validate an RFC 3161 DER request and return the DER-encoded CMS TimeStampToken.
    pub fn timestamp_request(&self, request_der: &[u8]) -> Result<Vec<u8>, TsaError> {
        if request_der.is_empty() || request_der.len() > MAX_REQUEST_SIZE {
            return Err(TsaError::InvalidRequest);
        }
        let request =
            TimeStampRequest::from_der(request_der).map_err(|_| TsaError::InvalidRequest)?;
        if request.version != Uint::new(&[1])? {
            return Err(TsaError::InvalidRequest);
        }
        if let Some(policy) = request.req_policy
            && policy != self.policy
        {
            return Err(TsaError::UnsupportedPolicy);
        }
        if request
            .extensions
            .as_ref()
            .is_some_and(|extensions| extensions.iter().any(|extension| extension.critical))
        {
            return Err(TsaError::InvalidRequest);
        }
        let imprint = &request.message_imprint;
        if imprint.hash_algorithm.oid != SHA256_OID
            || imprint.hash_algorithm.parameters.is_some()
            || imprint.hashed_message.as_bytes().len() != 32
        {
            return Err(TsaError::InvalidImprint);
        }

        let now = self.time_source.now().map_err(|_| TsaError::TimeSource)?;
        if now.duration_since(UNIX_EPOCH).is_err() {
            return Err(TsaError::TimeSource);
        }
        let validity = self.certificate.tbs_certificate().validity();
        if now < validity.not_before.to_system_time() || now > validity.not_after.to_system_time() {
            return Err(TsaError::InvalidCertificate(
                "certificate is not currently valid",
            ));
        }
        {
            let mut last = self.last_time.lock().map_err(|_| TsaError::TimeSource)?;
            if let Some(previous) = *last
                && now < previous
            {
                return Err(TsaError::TimeSource);
            }
            *last = Some(now);
        }
        let serial = loop {
            let current = self.serial.load(Ordering::SeqCst);
            let next = current.checked_add(1).ok_or(TsaError::Cms)?;
            match self.serial.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break current,
                Err(_) => continue,
            }
        };
        let serial_bytes = serial.to_be_bytes();
        let serial_bytes = serial_bytes
            .iter()
            .position(|b| *b != 0)
            .map(|index| &serial_bytes[index..])
            .unwrap_or(&[1]);
        let info = TstInfo {
            version: Uint::new(&[1])?,
            policy: self.policy,
            message_imprint: request.message_imprint,
            serial_number: Uint::new(serial_bytes)?,
            gen_time: GeneralizedTime::from_system_time(now).map_err(|_| TsaError::TimeSource)?,
            accuracy: None,
            ordering: false,
            nonce: request.nonce,
        };
        let info_der = info.to_der()?;
        self.build_token(&info_der)
    }

    fn build_token(&self, info_der: &[u8]) -> Result<Vec<u8>, TsaError> {
        let econtent = Any::encode_from(&OctetString::new(info_der.to_vec())?)?;
        let eci = EncapsulatedContentInfo {
            econtent_type: TST_INFO_OID,
            econtent: Some(econtent),
        };
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: self.certificate.tbs_certificate().issuer().clone(),
            serial_number: self.certificate.tbs_certificate().serial_number().clone(),
        });
        let digest_algorithm = AlgorithmIdentifierOwned {
            oid: SHA256_OID,
            parameters: None,
        };
        let mut signer_info = SignerInfoBuilder::new(sid, digest_algorithm.clone(), &eci, None)
            .map_err(|_| TsaError::Cms)?;
        let cert_der = self.certificate.to_der()?;
        let ess = EssSigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                cert_hash: OctetString::new(Sha256::digest(&cert_der).to_vec())?,
            }],
        };
        let ess_value = Any::encode_from(&ess)?;
        let ess_attribute = Attribute {
            oid: SIGNING_CERT_V2_OID,
            values: SetOfVec::try_from(vec![ess_value])?,
        };
        signer_info
            .add_signed_attribute(ess_attribute)
            .map_err(|_| TsaError::Cms)?;
        let content_type_value = Any::encode_from(&TST_INFO_OID)?;
        signer_info
            .add_signed_attribute(Attribute {
                oid: CONTENT_TYPE_ATTR_OID,
                values: SetOfVec::try_from(vec![content_type_value])?,
            })
            .map_err(|_| TsaError::Cms)?;
        let mut builder = SignedDataBuilder::new(&eci);
        builder
            .add_digest_algorithm(digest_algorithm)
            .map_err(|_| TsaError::Cms)?;
        builder
            .add_certificate(CertificateChoices::Certificate(self.certificate.clone()))
            .map_err(|_| TsaError::Cms)?;
        builder
            .add_signer_info::<SigningKey<MlDsa65>, MlDsaSignature<MlDsa65>>(
                signer_info,
                &self.signing_key,
            )
            .map_err(|_| TsaError::Cms)?;
        let content_info = builder.build().map_err(|_| TsaError::Cms)?;
        Ok(content_info.to_der()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EssSigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EssCertIdV2 {
    cert_hash: OctetString,
}

fn validate_tsa_certificate(
    certificate: &Certificate,
    signing_key: &SigningKey<MlDsa65>,
) -> Result<(), TsaError> {
    let tbs = certificate.tbs_certificate();
    if tbs.version() != x509_cert::Version::V3 {
        return Err(TsaError::InvalidCertificate("must be v3"));
    }
    if tbs.validity().not_before.to_unix_duration() >= tbs.validity().not_after.to_unix_duration() {
        return Err(TsaError::InvalidCertificate("invalid validity"));
    }
    let eku = tbs.extensions().and_then(|extensions| {
        extensions
            .iter()
            .find(|extension| extension.extn_id == const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE)
    });
    let eku = eku.ok_or(TsaError::InvalidCertificate("missing extendedKeyUsage"))?;
    if !eku.critical {
        return Err(TsaError::InvalidCertificate(
            "timeStamping EKU must be critical",
        ));
    }
    let parsed = ExtendedKeyUsage::from_der(eku.extn_value.as_bytes())
        .map_err(|_| TsaError::InvalidCertificate("malformed extendedKeyUsage"))?;
    if parsed.0.len() != 1 || parsed.0[0] != TIMESTAMPING_EKU_OID {
        return Err(TsaError::InvalidCertificate(
            "EKU must contain only id-kp-timeStamping",
        ));
    }
    let basic_constraints_ext = tbs
        .extensions()
        .and_then(|extensions| {
            extensions.iter().find(|extension| {
                extension.extn_id == const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS
            })
        })
        .ok_or(TsaError::InvalidCertificate("missing basicConstraints"))?;
    let basic_constraints = BasicConstraints::from_der(basic_constraints_ext.extn_value.as_bytes())
        .map_err(|_| TsaError::InvalidCertificate("malformed basicConstraints"))?;
    if basic_constraints.ca {
        return Err(TsaError::InvalidCertificate(
            "TSA certificate must not be a CA",
        ));
    }
    let key_usage_ext = tbs
        .extensions()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|extension| extension.extn_id == const_oid::db::rfc5280::ID_CE_KEY_USAGE)
        })
        .ok_or(TsaError::InvalidCertificate("missing keyUsage"))?;
    let key_usage = KeyUsage::from_der(key_usage_ext.extn_value.as_bytes())
        .map_err(|_| TsaError::InvalidCertificate("malformed keyUsage"))?;
    if !key_usage.digital_signature() {
        return Err(TsaError::InvalidCertificate(
            "keyUsage must allow digitalSignature",
        ));
    }
    let key_bytes = signing_key.verifying_key().encode().to_vec();
    let certificate_key = tbs.subject_public_key_info().subject_public_key.raw_bytes();
    if certificate_key != key_bytes.as_slice() {
        return Err(TsaError::KeyMismatch);
    }
    Ok(())
}

/// Verify a request's imprint against data before submitting it to a TSA.
pub fn sha256_message_imprint(data: &[u8]) -> Result<MessageImprint, TsaError> {
    Ok(MessageImprint {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: SHA256_OID,
            parameters: None,
        },
        hashed_message: OctetString::new(Sha256::digest(data).to_vec())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cms::{content_info::ContentInfo, signed_data::SignedData};
    use core::{str::FromStr, time::Duration};
    use der::{Decode, Encode};
    use ml_dsa::{EncodedVerifyingKey, Generate, Keypair, Verifier, VerifyingKey};
    use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
    use x509_cert::{
        builder::{Builder, CertificateBuilder, Error as BuilderError, profile::BuilderProfile},
        certificate::TbsCertificate,
        ext::Extension as X509Extension,
        ext::pkix::KeyUsages,
        name::Name,
        serial_number::SerialNumber,
        time::{Time, Validity},
    };

    struct TestTsaProfile {
        subject: Name,
    }
    impl BuilderProfile for TestTsaProfile {
        fn get_issuer(&self, subject: &Name) -> Name {
            subject.clone()
        }
        fn get_subject(&self) -> Name {
            self.subject.clone()
        }
        fn build_extensions(
            &self,
            _spk: SubjectPublicKeyInfoRef<'_>,
            _issuer_spk: SubjectPublicKeyInfoRef<'_>,
            _tbs: &TbsCertificate,
        ) -> Result<Vec<X509Extension>, BuilderError> {
            let eku = ExtendedKeyUsage(vec![TIMESTAMPING_EKU_OID]).to_der()?;
            let constraints = BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_der()?;
            let usage = KeyUsage(KeyUsages::DigitalSignature.into()).to_der()?;
            Ok(vec![
                X509Extension {
                    extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
                    critical: true,
                    extn_value: OctetString::new(constraints)?,
                },
                X509Extension {
                    extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
                    critical: true,
                    extn_value: OctetString::new(usage)?,
                },
                X509Extension {
                    extn_id: const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE,
                    critical: true,
                    extn_value: OctetString::new(eku)?,
                },
            ])
        }
    }

    fn test_signer() -> (SigningKey<MlDsa65>, Certificate) {
        let key = SigningKey::<MlDsa65>::generate();
        let subject = Name::from_str("CN=NexusQ Test TSA,O=NexusQ,C=US").unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_key(&key.verifying_key()).unwrap();
        let now = SystemTime::now();
        let validity = Validity::new(
            Time::try_from(now - Duration::from_secs(60)).unwrap(),
            Time::try_from(now + Duration::from_secs(3600)).unwrap(),
        );
        let builder = CertificateBuilder::new(
            TestTsaProfile { subject },
            SerialNumber::from(68u32),
            validity,
            spki,
        )
        .unwrap();
        let cert = builder
            .build::<SigningKey<MlDsa65>, MlDsaSignature<MlDsa65>>(&key)
            .unwrap();
        (key, cert)
    }

    #[test]
    fn emits_decodable_rfc3161_cms_token_and_echoes_nonce() {
        let (key, cert) = test_signer();
        let policy = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.68.1");
        let tsa = TimestampAuthority::new(policy, cert, key, 1).unwrap();
        let request = TimeStampRequest {
            version: Uint::new(&[1]).unwrap(),
            message_imprint: sha256_message_imprint(b"nexusq timestamp test").unwrap(),
            req_policy: Some(policy),
            nonce: Some(Uint::new(&[42]).unwrap()),
            cert_req: true,
            extensions: None,
        };
        let token_der = tsa.timestamp_request(&request.to_der().unwrap()).unwrap();
        let content_info = ContentInfo::from_der(&token_der).unwrap();
        assert_eq!(
            content_info.content_type,
            const_oid::db::rfc5911::ID_SIGNED_DATA
        );
        let signed_data = content_info.content.decode_as::<SignedData>().unwrap();
        assert_eq!(signed_data.signer_infos.0.len(), 1);
        assert_eq!(signed_data.certificates.as_ref().unwrap().0.len(), 1);
        let signer_info = signed_data.signer_infos.0.get(0).unwrap();
        assert_eq!(
            signer_info.signature_algorithm.oid,
            const_oid::db::fips204::ID_ML_DSA_65
        );
        let signed_attributes_der = signer_info.signed_attrs.as_ref().unwrap().to_der().unwrap();
        let cert = match signed_data.certificates.as_ref().unwrap().0.get(0).unwrap() {
            CertificateChoices::Certificate(cert) => cert,
            _ => panic!("unexpected certificate choice"),
        };
        let encoded_public_key = EncodedVerifyingKey::<MlDsa65>::try_from(
            cert.tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes(),
        )
        .unwrap();
        let public_key = VerifyingKey::<MlDsa65>::decode(&encoded_public_key);
        let signature =
            MlDsaSignature::<MlDsa65>::try_from(signer_info.signature.as_bytes()).unwrap();
        public_key
            .verify(&signed_attributes_der, &signature)
            .unwrap();
        let econtent = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .unwrap()
            .decode_as::<OctetString>()
            .unwrap();
        let info = TstInfo::from_der(econtent.as_bytes()).unwrap();
        assert_eq!(info.version, Uint::new(&[1]).unwrap());
        assert_eq!(info.policy, policy);
        assert_eq!(info.nonce, request.nonce);
        assert_eq!(info.message_imprint, request.message_imprint);
        assert_eq!(info.serial_number, Uint::new(&[1]).unwrap());
    }

    #[test]
    fn rejects_bad_imprint_and_wrong_policy() {
        let (key, cert) = test_signer();
        let policy = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.68.1");
        let tsa = TimestampAuthority::new(policy, cert, key, 1).unwrap();
        let mut request = TimeStampRequest {
            version: Uint::new(&[1]).unwrap(),
            message_imprint: sha256_message_imprint(b"x").unwrap(),
            req_policy: None,
            nonce: None,
            cert_req: false,
            extensions: None,
        };
        request.message_imprint.hashed_message = OctetString::new(vec![0; 31]).unwrap();
        assert!(matches!(
            tsa.timestamp_request(&request.to_der().unwrap()),
            Err(TsaError::InvalidImprint)
        ));
        request.message_imprint = sha256_message_imprint(b"x").unwrap();
        request.req_policy = Some(ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.68.2"));
        assert!(matches!(
            tsa.timestamp_request(&request.to_der().unwrap()),
            Err(TsaError::UnsupportedPolicy)
        ));
    }
}

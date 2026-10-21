//! X.509 certificate issuance using NexusQ post-quantum signing keys.
//!
//! ASN.1/X.509 encoding is delegated to `x509-cert`; signature algorithm identifiers
//! come from the selected cryptographic key implementation.

use core::time::Duration;

/// Re-export the key and ASN.1 crates used by the public issuance API.
pub use ml_dsa;
pub use slh_dsa;
pub use x509_cert;

use der::{
    EncodePem,
    asn1::{BitString, Ia5String, ObjectIdentifier},
};
use ml_dsa::{
    MlDsa65, MlDsaParams, Signature as MlDsaSignature, SigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use signature::{Keypair, Signer};
use slh_dsa::{
    ParameterSet as SlhDsaParameterSet, Signature as SlhDsaSignature,
    SigningKey as SlhDsaSigningKey,
};
use x509_cert::{
    Certificate,
    builder::{
        Builder, CertificateBuilder, Error,
        profile::{BuilderProfile, cabf},
    },
    ext::{
        Extension, ToExtension,
        pkix::{
            AccessDescription, AuthorityInfoAccessSyntax, CrlDistributionPoints,
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName},
        },
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{
        AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
        SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
    },
    time::Validity,
};

/// A signer interface for ML-DSA-65 private keys held outside the process, such as a PKCS#11 HSM.
/// Implementations return only the public key and detached signature bytes; they must never export
/// the private key material.
pub trait MlDsa65Signer: Send + Sync {
    /// Public key corresponding to the protected private key.
    fn public_key(&self) -> MlDsaVerifyingKey<MlDsa65>;
    /// Sign a message without exporting the private key.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

impl MlDsa65Signer for SigningKey<MlDsa65> {
    fn public_key(&self) -> MlDsaVerifyingKey<MlDsa65> {
        Keypair::verifying_key(self)
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let signature = Signer::<MlDsaSignature<MlDsa65>>::try_sign(self, message)
            .map_err(|error| error.to_string())?;
        Ok(signature.encode().to_vec())
    }
}

/// Error returned when assembling a certificate with an external ML-DSA-65 signer.
#[derive(Debug, thiserror::Error)]
pub enum ExternalSignError {
    /// Building the TBSCertificate failed.
    #[error("X.509 builder failed: {0}")]
    Builder(#[from] Error),
    /// Encoding the signature BIT STRING failed.
    #[error("invalid external signature encoding: {0}")]
    Der(#[from] der::Error),
    /// The external signer failed. Implementations should return sanitized error text.
    #[error("external ML-DSA-65 signer failed: {0}")]
    Signer(String),
}

struct ExternalPublicKeySigner(MlDsaVerifyingKey<MlDsa65>);
impl Keypair for ExternalPublicKeySigner {
    type VerifyingKey = MlDsaVerifyingKey<MlDsa65>;
    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.clone()
    }
}
impl DynSignatureAlgorithmIdentifier for ExternalPublicKeySigner {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: const_oid::db::fips204::ID_ML_DSA_65,
            parameters: None,
        })
    }
}

/// Assemble a certificate with a PKCS#11/HSM-backed ML-DSA-65 signing operation.
///
/// The builder first finalizes the exact DER TBSCertificate. The callback signs those bytes inside
/// the external provider; this function then attaches the returned signature and algorithm ID.
/// No private key bytes are accepted by or returned from this API.
pub fn build_certificate_with_external_ml_dsa65_signer<P, F>(
    mut builder: CertificateBuilder<P>,
    public_key: MlDsaVerifyingKey<MlDsa65>,
    sign: F,
) -> Result<Certificate, ExternalSignError>
where
    P: BuilderProfile,
    F: FnOnce(&[u8]) -> Result<Vec<u8>, String>,
{
    let signer = ExternalPublicKeySigner(public_key);
    let tbs_der = builder.finalize(&signer)?;
    let signature = sign(&tbs_der).map_err(ExternalSignError::Signer)?;
    let signature = BitString::from_bytes(&signature)?;
    Ok(builder.assemble(signature, &signer)?)
}

/// Issue a certificate with an explicit profile, subject public key, and issuer signer.
///
/// The caller is responsible for selecting a profile appropriate to the certificate's
/// purpose and ensuring that the issuer key is authorized to issue it.
pub fn issue_certificate<P, S, Sig>(
    profile: P,
    serial_number: SerialNumber,
    validity: Validity,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    issuer_signer: &S,
) -> Result<Certificate, Error>
where
    P: BuilderProfile,
    S: Signer<Sig> + Keypair + DynSignatureAlgorithmIdentifier,
    S::VerifyingKey: EncodePublicKey,
    Sig: SignatureBitStringEncoding,
{
    let builder =
        CertificateBuilder::new(profile, serial_number, validity, subject_public_key_info)?;
    builder.build::<S, Sig>(issuer_signer)
}

/// Issue a self-signed RFC 5280 root certificate using any supported ML-DSA parameter set.
///
/// The subject must satisfy the CA/Browser Forum root naming profile (`C`, `O`, and `CN`).
/// Standard root-CA extensions and the selected ML-DSA algorithm identifier are supplied by
/// the X.509 builder and key implementation.
pub fn issue_self_signed_ml_dsa_root<P>(
    subject: Name,
    serial_number: SerialNumber,
    validity: Validity,
    signer: &SigningKey<P>,
) -> Result<Certificate, Error>
where
    P: MlDsaParams,
    SigningKey<P>: Signer<MlDsaSignature<P>> + Keypair + DynSignatureAlgorithmIdentifier,
    <SigningKey<P> as Keypair>::VerifyingKey: EncodePublicKey,
    MlDsaSignature<P>: SignatureBitStringEncoding,
{
    let profile = cabf::Root::new(false, subject)?;
    let subject_public_key_info = SubjectPublicKeyInfoOwned::from_key(&signer.verifying_key())?;
    issue_certificate::<_, _, MlDsaSignature<P>>(
        profile,
        serial_number,
        validity,
        subject_public_key_info,
        signer,
    )
}

/// Issue a self-signed RFC 5280 root certificate using ML-DSA-65.
pub fn issue_self_signed_ml_dsa65_root(
    subject: Name,
    serial_number: SerialNumber,
    validity: Validity,
    signer: &SigningKey<MlDsa65>,
) -> Result<Certificate, Error> {
    issue_self_signed_ml_dsa_root(subject, serial_number, validity, signer)
}

/// Issue a subordinate CA certificate using any supported ML-DSA parameter set.
pub fn issue_ml_dsa_subordinate_ca<P>(
    subject: Name,
    issuer: Name,
    serial_number: SerialNumber,
    validity: Validity,
    subject_key: &MlDsaVerifyingKey<P>,
    issuer_signer: &SigningKey<P>,
    path_len_constraint: Option<u8>,
) -> Result<Certificate, Error>
where
    P: MlDsaParams,
    SigningKey<P>: Signer<MlDsaSignature<P>> + Keypair + DynSignatureAlgorithmIdentifier,
    <SigningKey<P> as Keypair>::VerifyingKey: EncodePublicKey,
    MlDsaSignature<P>: SignatureBitStringEncoding,
    MlDsaVerifyingKey<P>: EncodePublicKey,
{
    let profile = cabf::tls::Subordinate {
        issuer,
        subject,
        path_len_constraint,
        emits_ocsp_response: false,
        client_auth: false,
    };
    let subject_public_key_info = SubjectPublicKeyInfoOwned::from_key(subject_key)?;
    issue_certificate::<_, _, MlDsaSignature<P>>(
        profile,
        serial_number,
        validity,
        subject_public_key_info,
        issuer_signer,
    )
}

/// Validated HTTPS locations advertised by issued certificates for revocation checking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationUrls {
    ocsp_url: String,
    crl_url: String,
}

impl RevocationUrls {
    /// Create revocation URLs. HTTPS, an authority/host, ASCII syntax, and no credentials or
    /// fragments are required so the URLs can be safely embedded in X.509 IA5String fields.
    pub fn new(
        ocsp_url: impl Into<String>,
        crl_url: impl Into<String>,
    ) -> Result<Self, RevocationUrlError> {
        let ocsp_url = ocsp_url.into();
        let crl_url = crl_url.into();
        if !valid_revocation_url(&ocsp_url) || !valid_revocation_url(&crl_url) {
            return Err(RevocationUrlError);
        }
        Ok(Self { ocsp_url, crl_url })
    }

    /// OCSP responder URL embedded in the Authority Information Access extension.
    pub fn ocsp_url(&self) -> &str {
        &self.ocsp_url
    }

    /// CRL distribution URL embedded in the CRL Distribution Points extension.
    pub fn crl_url(&self) -> &str {
        &self.crl_url
    }
}

/// Invalid or unsafe revocation URL supplied to [`RevocationUrls::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationUrlError;

impl core::fmt::Display for RevocationUrlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "revocation URLs must be valid ASCII HTTPS URLs without credentials or fragments",
        )
    }
}

impl core::error::Error for RevocationUrlError {}

fn valid_revocation_url(url: &str) -> bool {
    if !url.is_ascii()
        || url.chars().any(char::is_control)
        || url.contains('#')
        || url.contains('@')
        || url.chars().any(char::is_whitespace)
    {
        return false;
    }
    let Some(authority_and_path) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = authority_and_path
        .split(['/', '?'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.starts_with(':') || authority.contains('@') {
        return false;
    }
    let host = if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        if end <= 1 {
            return false;
        }
        let suffix = &authority[end + 1..];
        if !suffix.is_empty() && (!suffix.starts_with(':') || suffix[1..].parse::<u16>().is_err()) {
            return false;
        }
        &authority[..=end]
    } else {
        let mut parts = authority.split(':');
        let host = parts.next().unwrap_or_default();
        if let Some(port) = parts.next() {
            if port.is_empty() || port.parse::<u16>().is_err() || parts.next().is_some() {
                return false;
            }
        }
        host
    };
    !host.is_empty()
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'.'
                || b == b'-'
                || b == b'['
                || b == b']'
                || b == b':'
        })
}

struct RevocationAwareSubordinate {
    inner: cabf::tls::Subordinate,
    urls: RevocationUrls,
}

impl BuilderProfile for RevocationAwareSubordinate {
    fn get_issuer(&self, subject: &Name) -> Name {
        self.inner.get_issuer(subject)
    }
    fn get_subject(&self) -> Name {
        self.inner.get_subject()
    }
    fn build_extensions(
        &self,
        spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        issuer_spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::TbsCertificate,
    ) -> Result<Vec<Extension>, Error> {
        let mut extensions = self.inner.build_extensions(spk, issuer_spk, tbs)?;
        let ocsp_access = AuthorityInfoAccessSyntax(vec![AccessDescription {
            access_method: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1"),
            access_location: GeneralName::UniformResourceIdentifier(Ia5String::new(
                &self.urls.ocsp_url,
            )?),
        }]);
        extensions.push(ocsp_access.to_extension(tbs.subject(), &extensions)?);
        let crl_points = CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(Ia5String::new(&self.urls.crl_url)?),
            ])),
            reasons: None,
            crl_issuer: None,
        }]);
        extensions.push(crl_points.to_extension(tbs.subject(), &extensions)?);
        Ok(extensions)
    }
}

/// Issue an ML-DSA subordinate CA certificate with explicit OCSP and CRL discovery URLs.
///
/// In addition to the RFC 5280 CA extensions, the certificate advertises the OCSP endpoint in
/// Authority Information Access and the CRL endpoint in CRL Distribution Points. The URLs must
/// be HTTPS and are validated by [`RevocationUrls::new`].
#[allow(clippy::too_many_arguments)] // Mirrors the existing subordinate issuer API and adds revocation endpoints.
pub fn issue_ml_dsa_subordinate_ca_with_revocation_urls<P>(
    subject: Name,
    issuer: Name,
    serial_number: SerialNumber,
    validity: Validity,
    subject_key: &MlDsaVerifyingKey<P>,
    issuer_signer: &SigningKey<P>,
    path_len_constraint: Option<u8>,
    urls: RevocationUrls,
) -> Result<Certificate, Error>
where
    P: MlDsaParams,
    SigningKey<P>: Signer<MlDsaSignature<P>> + Keypair + DynSignatureAlgorithmIdentifier,
    <SigningKey<P> as Keypair>::VerifyingKey: EncodePublicKey,
    MlDsaSignature<P>: SignatureBitStringEncoding,
    MlDsaVerifyingKey<P>: EncodePublicKey,
{
    let profile = RevocationAwareSubordinate {
        inner: cabf::tls::Subordinate {
            issuer,
            subject,
            path_len_constraint,
            emits_ocsp_response: true,
            client_auth: false,
        },
        urls,
    };
    let subject_public_key_info = SubjectPublicKeyInfoOwned::from_key(subject_key)?;
    issue_certificate::<_, _, MlDsaSignature<P>>(
        profile,
        serial_number,
        validity,
        subject_public_key_info,
        issuer_signer,
    )
}

/// Issue an ML-DSA-65 subordinate CA certificate signed by an ML-DSA-65 issuer.
///
/// The supplied subject key may be distinct from the issuer key. The profile adds CA
/// constraints, key usage, subject-key identifier, and authority-key identifier extensions.
pub fn issue_ml_dsa65_subordinate_ca(
    subject: Name,
    issuer: Name,
    serial_number: SerialNumber,
    validity: Validity,
    subject_key: &MlDsaVerifyingKey<MlDsa65>,
    issuer_signer: &SigningKey<MlDsa65>,
    path_len_constraint: Option<u8>,
) -> Result<Certificate, Error> {
    issue_ml_dsa_subordinate_ca(
        subject,
        issuer,
        serial_number,
        validity,
        subject_key,
        issuer_signer,
        path_len_constraint,
    )
}

/// Issue a self-signed RFC 5280 root certificate using an SLH-DSA key.
///
/// The parameter set selects the FIPS 205 algorithm and its standard algorithm identifier.
/// Interoperability depends on the consuming OpenSSL/Bouncy Castle version supporting that
/// SLH-DSA parameter set and its X.509 algorithm identifier.
pub fn issue_self_signed_slh_dsa_root<P>(
    subject: Name,
    serial_number: SerialNumber,
    validity: Validity,
    signer: &SlhDsaSigningKey<P>,
) -> Result<Certificate, Error>
where
    P: SlhDsaParameterSet,
    SlhDsaSigningKey<P>: Signer<SlhDsaSignature<P>> + Keypair + DynSignatureAlgorithmIdentifier,
    <SlhDsaSigningKey<P> as Keypair>::VerifyingKey: EncodePublicKey,
    SlhDsaSignature<P>: SignatureBitStringEncoding,
{
    let profile = cabf::Root::new(false, subject)?;
    let subject_public_key_info = SubjectPublicKeyInfoOwned::from_key(&signer.verifying_key())?;
    issue_certificate::<_, _, SlhDsaSignature<P>>(
        profile,
        serial_number,
        validity,
        subject_public_key_info,
        signer,
    )
}

/// Encode a certificate as PEM with the standard `CERTIFICATE` label.
pub fn certificate_to_pem(certificate: &Certificate) -> Result<String, der::Error> {
    certificate.to_pem(der::pem::LineEnding::LF)
}

/// Construct a validity period beginning now and ending after `duration`.
pub fn validity_for(duration: Duration) -> Result<Validity, Error> {
    Validity::from_now(duration).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::{
        RevocationUrls, issue_ml_dsa_subordinate_ca_with_revocation_urls,
        issue_ml_dsa65_subordinate_ca, issue_self_signed_ml_dsa_root,
        issue_self_signed_ml_dsa65_root, issue_self_signed_slh_dsa_root, validity_for,
    };
    use core::{str::FromStr, time::Duration};
    use der::{Decode, DecodePem, Encode};
    use ml_dsa::{Generate, Keypair, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, Verifier};
    use slh_dsa::{Shake128f, SigningKey as SlhSigningKey};
    use x509_cert::spki::DynSignatureAlgorithmIdentifier;
    use x509_cert::{Certificate, certificate::Version, name::Name, serial_number::SerialNumber};

    #[test]
    fn issues_and_verifies_ml_dsa65_root_certificate() {
        let signer = SigningKey::<MlDsa65>::generate();
        let subject = Name::from_str("CN=NexusQ Test Root,O=NexusQ,C=US").unwrap();
        let validity = validity_for(Duration::from_secs(24 * 60 * 60)).unwrap();
        let certificate =
            issue_self_signed_ml_dsa65_root(subject, SerialNumber::from(42u32), validity, &signer)
                .unwrap();

        let der = certificate.to_der().unwrap();
        let decoded = Certificate::from_der(&der).unwrap();
        assert_eq!(decoded, certificate);
        let pem = super::certificate_to_pem(&decoded).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(Certificate::from_pem(&pem).unwrap(), decoded);
        assert_eq!(decoded.tbs_certificate().version(), Version::V3);
        assert_eq!(
            decoded.signature_algorithm().oid,
            signer.signature_algorithm_identifier().unwrap().oid
        );

        let tbs = decoded.tbs_certificate().to_der().unwrap();
        let signature_bytes = decoded.signature().as_bytes().unwrap();
        let signature = Signature::<MlDsa65>::try_from(signature_bytes).unwrap();
        signer.verifying_key().verify(&tbs, &signature).unwrap();
    }

    #[test]
    fn issues_roots_for_all_ml_dsa_parameter_sets() {
        let subject = Name::from_str("CN=NexusQ ML-DSA Root,O=NexusQ,C=US").unwrap();
        let validity = validity_for(Duration::from_secs(60)).unwrap();
        let key44 = SigningKey::<MlDsa44>::generate();
        let cert44 = issue_self_signed_ml_dsa_root(
            subject.clone(),
            SerialNumber::from(47u32),
            validity,
            &key44,
        )
        .unwrap();
        assert_eq!(
            cert44.signature_algorithm().oid,
            key44.signature_algorithm_identifier().unwrap().oid
        );

        let key87 = SigningKey::<MlDsa87>::generate();
        let cert87 =
            issue_self_signed_ml_dsa_root(subject, SerialNumber::from(48u32), validity, &key87)
                .unwrap();
        assert_eq!(
            cert87.signature_algorithm().oid,
            key87.signature_algorithm_identifier().unwrap().oid
        );
    }

    #[test]
    fn issues_subordinate_ca_signed_by_ml_dsa65_issuer() {
        let issuer_signer = SigningKey::<MlDsa65>::generate();
        let subject_signer = SigningKey::<MlDsa65>::generate();
        let issuer = Name::from_str("CN=NexusQ Root,O=NexusQ,C=US").unwrap();
        let subject = Name::from_str("CN=NexusQ Subordinate,O=NexusQ,C=US").unwrap();
        let validity = validity_for(Duration::from_secs(24 * 60 * 60)).unwrap();
        let certificate = issue_ml_dsa65_subordinate_ca(
            subject,
            issuer,
            SerialNumber::from(44u32),
            validity,
            &subject_signer.verifying_key(),
            &issuer_signer,
            Some(0),
        )
        .unwrap();

        let tbs = certificate.tbs_certificate().to_der().unwrap();
        let signature =
            Signature::<MlDsa65>::try_from(certificate.signature().as_bytes().unwrap()).unwrap();
        issuer_signer
            .verifying_key()
            .verify(&tbs, &signature)
            .unwrap();
        assert_eq!(
            certificate.signature_algorithm().oid,
            issuer_signer.signature_algorithm_identifier().unwrap().oid
        );
    }

    #[test]
    fn subordinate_certificate_publishes_ocsp_and_crl_urls() {
        let issuer_signer = SigningKey::<MlDsa65>::generate();
        let subject_signer = SigningKey::<MlDsa65>::generate();
        let issuer = Name::from_str("CN=NexusQ Root,O=NexusQ,C=US").unwrap();
        let subject = Name::from_str("CN=NexusQ Revocation Subordinate,O=NexusQ,C=US").unwrap();
        let urls = RevocationUrls::new(
            "https://pki.example.test/ocsp",
            "https://pki.example.test/crl.pem",
        )
        .unwrap();
        let certificate = issue_ml_dsa_subordinate_ca_with_revocation_urls(
            subject,
            issuer,
            SerialNumber::from(49u32),
            validity_for(Duration::from_secs(3600)).unwrap(),
            &subject_signer.verifying_key(),
            &issuer_signer,
            Some(0),
            urls,
        )
        .unwrap();
        let tbs = certificate.tbs_certificate();
        let ext_opt = tbs.extensions();
        let extensions = ext_opt.as_ref().unwrap();
        assert!(
            extensions
                .iter()
                .any(|ext| ext.extn_id.to_string() == "1.3.6.1.5.5.7.1.1")
        );
        assert!(
            extensions
                .iter()
                .any(|ext| ext.extn_id.to_string() == "2.5.29.31")
        );
    }

    #[test]
    fn revocation_urls_reject_http_credentials_and_fragments() {
        assert!(RevocationUrls::new("http://pki.example/ocsp", "https://pki.example/crl").is_err());
        assert!(
            RevocationUrls::new("https://user@pki.example/ocsp", "https://pki.example/crl")
                .is_err()
        );
        assert!(
            RevocationUrls::new(
                "https://pki.example/ocsp#fragment",
                "https://pki.example/crl"
            )
            .is_err()
        );
        assert!(RevocationUrls::new("https://pki.example/ocsp", "https://pki.example/crl").is_ok());
    }

    #[test]
    fn issues_and_verifies_slh_dsa_root_certificate() {
        let mut rng = rand::rng();
        let signer = SlhSigningKey::<Shake128f>::new(&mut rng);
        let subject = Name::from_str("CN=NexusQ SLH Test Root,O=NexusQ,C=US").unwrap();
        let validity = validity_for(Duration::from_secs(24 * 60 * 60)).unwrap();
        let certificate =
            issue_self_signed_slh_dsa_root(subject, SerialNumber::from(45u32), validity, &signer)
                .unwrap();

        let der = certificate.to_der().unwrap();
        let decoded = Certificate::from_der(&der).unwrap();
        assert_eq!(decoded, certificate);
        let tbs = decoded.tbs_certificate().to_der().unwrap();
        let signature =
            slh_dsa::Signature::<Shake128f>::try_from(decoded.signature().as_bytes().unwrap())
                .unwrap();
        signer.verifying_key().verify(&tbs, &signature).unwrap();
    }

    #[test]
    fn rejects_malformed_der_and_tampered_signature() {
        assert!(Certificate::from_der(&[0x30, 0x00]).is_err());

        let signer = SigningKey::<MlDsa65>::generate();
        let subject = Name::from_str("CN=NexusQ Tamper Test Root,O=NexusQ,C=US").unwrap();
        let validity = validity_for(Duration::from_secs(60)).unwrap();
        let certificate =
            issue_self_signed_ml_dsa65_root(subject, SerialNumber::from(46u32), validity, &signer)
                .unwrap();
        let tbs = certificate.tbs_certificate().to_der().unwrap();
        let mut signature_bytes = certificate.signature().as_bytes().unwrap().to_vec();
        signature_bytes[0] ^= 0x01;
        let result = Signature::<MlDsa65>::try_from(signature_bytes.as_slice())
            .and_then(|signature| signer.verifying_key().verify(&tbs, &signature));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_ca_subject_name() {
        let signer = SigningKey::<MlDsa65>::generate();
        let subject = Name::from_str("CN=Missing Required CA Attributes").unwrap();
        let validity = validity_for(Duration::from_secs(60)).unwrap();
        assert!(
            issue_self_signed_ml_dsa65_root(subject, SerialNumber::from(43u32), validity, &signer,)
                .is_err()
        );
    }
}

#[cfg(feature = "experimental-composite")]
pub mod composite;

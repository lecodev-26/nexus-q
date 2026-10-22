//! Experimental composite ML-DSA-65 + Ed25519 X.509 support.
//!
//! This module implements the current LAMPS `draft-ietf-lamps-pq-composite-sigs-19`
//! profile `id-MLDSA65-Ed25519-SHA512` (OID 1.3.6.1.5.5.7.6.48). It is feature-gated
//! because the specification is an Internet-Draft, not a final RFC. Do not treat this
//! OID/profile as a stable long-term interoperability contract.

use der::{Document, Encode, asn1::BitString};
use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::{
    Generate, MlDsa65, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use sha2::{Digest, Sha512};
use signature::{Keypair, Signer, Verifier};
use x509_cert::{
    Certificate,
    builder::{Error, profile::cabf},
    name::Name,
    serial_number::SerialNumber,
    spki::{
        AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
        ObjectIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
    },
    time::Validity,
};

use crate::{issue_certificate, validity_for};

const COMPOSITE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.48");
const LABEL: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";
const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
const ED25519_SIGNATURE_LEN: usize = 64;

fn message_representative(message: &[u8]) -> Vec<u8> {
    let digest = Sha512::digest(message);
    let mut representative = Vec::with_capacity(PREFIX.len() + LABEL.len() + 1 + digest.len());
    representative.extend_from_slice(PREFIX);
    representative.extend_from_slice(LABEL);
    representative.push(0); // Empty application context, length encoded as one octet.
    representative.extend_from_slice(&digest);
    representative
}

/// Freshly generated component keys for the draft ML-DSA-65 + Ed25519 composite profile.
/// Component key material must not be reused as standalone keys or in another composite.
pub struct CompositeSigningKey {
    ml_dsa: MlDsaSigningKey<MlDsa65>,
    ed25519: Ed25519SigningKey,
}

/// Public component keys for the draft ML-DSA-65 + Ed25519 composite profile.
#[derive(Clone)]
pub struct CompositeVerifyingKey {
    ml_dsa: MlDsaVerifyingKey<MlDsa65>,
    ed25519: Ed25519VerifyingKey,
}

/// Raw concatenation of the ML-DSA-65 signature followed by the Ed25519 signature.
#[derive(Clone, Debug)]
pub struct CompositeSignature(Vec<u8>);

impl CompositeSigningKey {
    /// Generate fresh ML-DSA-65 and Ed25519 component keys.
    pub fn generate() -> Self {
        let ml_dsa = MlDsaSigningKey::<MlDsa65>::generate();
        let mut rng = rand::rng();
        let ed25519 = Ed25519SigningKey::generate(&mut rng);
        Self { ml_dsa, ed25519 }
    }
}

impl Keypair for CompositeSigningKey {
    type VerifyingKey = CompositeVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        CompositeVerifyingKey {
            ml_dsa: self.ml_dsa.verifying_key(),
            ed25519: self.ed25519.verifying_key(),
        }
    }
}

impl DynSignatureAlgorithmIdentifier for CompositeSigningKey {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: COMPOSITE_OID,
            parameters: None,
        })
    }
}

impl Signer<CompositeSignature> for CompositeSigningKey {
    fn try_sign(&self, message: &[u8]) -> Result<CompositeSignature, signature::Error> {
        let representative = message_representative(message);
        let ml_dsa_signature = self
            .ml_dsa
            .expanded_key()
            .sign_deterministic(&representative, LABEL)
            .map_err(|_| signature::Error::new())?;
        let ed25519_signature = self.ed25519.sign(&representative);
        let ml_dsa_bytes = ml_dsa_signature.encode();
        let mut bytes = Vec::from(&ml_dsa_bytes[..]);
        bytes.extend_from_slice(&ed25519_signature.to_bytes());
        Ok(CompositeSignature(bytes))
    }
}

impl SignatureBitStringEncoding for CompositeSignature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(&self.0)
    }
}

impl EncodePublicKey for CompositeVerifyingKey {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<Document> {
        let ml_dsa_bytes = self.ml_dsa.encode();
        let mut bytes = Vec::from(&ml_dsa_bytes[..]);
        bytes.extend_from_slice(self.ed25519.as_bytes());
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: COMPOSITE_OID,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&bytes)?,
        };
        Ok(Document::try_from(spki.to_der()?)?)
    }
}

impl Verifier<CompositeSignature> for CompositeVerifyingKey {
    fn verify(
        &self,
        message: &[u8],
        signature: &CompositeSignature,
    ) -> Result<(), signature::Error> {
        if signature.0.len() != ML_DSA_65_SIGNATURE_LEN + ED25519_SIGNATURE_LEN {
            return Err(signature::Error::new());
        }
        let representative = message_representative(message);
        let ml_dsa_signature =
            MlDsaSignature::<MlDsa65>::try_from(&signature.0[..ML_DSA_65_SIGNATURE_LEN])
                .map_err(|_| signature::Error::new())?;
        if !self
            .ml_dsa
            .verify_with_context(&representative, LABEL, &ml_dsa_signature)
        {
            return Err(signature::Error::new());
        }
        let ed25519_signature =
            Ed25519Signature::from_slice(&signature.0[ML_DSA_65_SIGNATURE_LEN..])
                .map_err(|_| signature::Error::new())?;
        self.ed25519
            .verify(&representative, &ed25519_signature)
            .map_err(|_| signature::Error::new())
    }
}

impl CompositeSignature {
    /// Construct from a serialized composite signature, rejecting incorrect lengths.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        if bytes.len() != ML_DSA_65_SIGNATURE_LEN + ED25519_SIGNATURE_LEN {
            return Err(signature::Error::new());
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Return the serialized signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Issue an experimental self-signed root using draft ML-DSA-65 + Ed25519 composite signatures.
pub fn issue_self_signed_composite_root(
    subject: Name,
    serial_number: SerialNumber,
    validity: Validity,
    signer: &CompositeSigningKey,
) -> Result<Certificate, Error> {
    let profile = cabf::Root::new(false, subject)?;
    let subject_public_key_info = SubjectPublicKeyInfoOwned::from_key(&signer.verifying_key())?;
    issue_certificate::<_, _, CompositeSignature>(
        profile,
        serial_number,
        validity,
        subject_public_key_info,
        signer,
    )
}

/// Convenience helper for an experimental composite root valid for the requested duration.
pub fn issue_composite_root_for(
    subject: Name,
    serial_number: SerialNumber,
    duration: core::time::Duration,
    signer: &CompositeSigningKey,
) -> Result<Certificate, Error> {
    issue_self_signed_composite_root(subject, serial_number, validity_for(duration)?, signer)
}

#[cfg(test)]
mod tests {
    use super::{COMPOSITE_OID, CompositeSignature, CompositeSigningKey, issue_composite_root_for};
    use crate::certificate_to_pem;
    use core::{str::FromStr, time::Duration};
    use der::{Decode, Encode};
    use signature::{Keypair, Verifier};
    use x509_cert::{Certificate, certificate::Version, name::Name, serial_number::SerialNumber};

    #[test]
    fn issues_and_verifies_experimental_composite_root() {
        let signer = CompositeSigningKey::generate();
        let subject = Name::from_str("CN=NexusQ Composite Test Root,O=NexusQ,C=US").unwrap();
        let cert = issue_composite_root_for(
            subject,
            SerialNumber::from(90u32),
            Duration::from_secs(3600),
            &signer,
        )
        .unwrap();
        let der = cert.to_der().unwrap();
        let decoded = Certificate::from_der(&der).unwrap();
        assert_eq!(decoded, cert);
        assert_eq!(decoded.tbs_certificate().version(), Version::V3);
        assert_eq!(decoded.signature_algorithm().oid, COMPOSITE_OID);
        assert_eq!(decoded.tbs_certificate().signature().oid, COMPOSITE_OID);
        let tbs = decoded.tbs_certificate().to_der().unwrap();
        let sig = CompositeSignature::from_bytes(decoded.signature().as_bytes().unwrap()).unwrap();
        signer.verifying_key().verify(&tbs, &sig).unwrap();
        assert!(
            certificate_to_pem(&decoded)
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
    }
}

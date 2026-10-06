//! Signed credentials.
//!
//! New credentials use ML-DSA-65. Legacy Ed25519 credentials remain
//! verifiable for compatibility. The exact issuer key and signature
//! algorithm are authenticated by the signed payload.

use serde::{Deserialize, Serialize};

use crate::crypto::{
    pq_sign::{self, PqSignError},
    sign::{SignError, Signature, SigningKey, VerifyingKey},
};
use crate::vault::{KeyId, Timestamp};

use super::id::IdentityId;

/// Current credential schema version.
pub const CURRENT_VERSION: u8 = 3;

/// Legacy credential schema version.
pub const LEGACY_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CredentialSignatureAlgorithm {
    #[default]
    Ed25519,
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub version: u8,
    pub subject: IdentityId,
    pub issuer: IdentityId,
    pub issuer_key_id: KeyId,
    /// Missing on legacy v2 credentials; defaults to Ed25519.
    #[serde(default)]
    pub signature_algorithm: CredentialSignatureAlgorithm,
    #[serde(with = "serde_bytes")]
    pub claims: Vec<u8>,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedPayloadV2 {
    version: u8,
    subject: IdentityId,
    issuer: IdentityId,
    issuer_key_id: KeyId,
    #[serde(with = "serde_bytes")]
    claims: Vec<u8>,
    issued_at: Timestamp,
    expires_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedPayloadV3 {
    version: u8,
    subject: IdentityId,
    issuer: IdentityId,
    issuer_key_id: KeyId,
    signature_algorithm: CredentialSignatureAlgorithm,
    #[serde(with = "serde_bytes")]
    claims: Vec<u8>,
    issued_at: Timestamp,
    expires_at: Option<Timestamp>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    #[error("cbor error: {0}")]
    Cbor(#[from] crate::vault::CborError),
    #[error("signature error: {0}")]
    Signature(#[from] SignError),
    #[error("post-quantum signature error: {0}")]
    PqSignature(#[from] PqSignError),
    #[error("unsupported credential version: {0}")]
    UnsupportedVersion(u8),
    #[error("credential expired")]
    Expired,
    #[error("credential signature algorithm does not match supplied key")]
    AlgorithmMismatch,
}

impl Credential {
    #[allow(clippy::too_many_arguments)]
    fn issue_v3(
        algorithm: CredentialSignatureAlgorithm,
        issuer_key_id: KeyId,
        issuer: IdentityId,
        subject: IdentityId,
        claims: Vec<u8>,
        issued_at: Timestamp,
        expires_at: Option<Timestamp>,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, CredentialError> {
        let credential = Credential {
            version: CURRENT_VERSION,
            subject,
            issuer,
            issuer_key_id,
            signature_algorithm: algorithm,
            claims,
            issued_at,
            expires_at,
            signature,
        };
        Ok(crate::vault::to_vec(&credential)?)
    }

    /// Produces a current-schema Ed25519 credential for compatibility.
    pub fn issue(
        signing_key: &SigningKey,
        issuer: IdentityId,
        issuer_key_id: KeyId,
        subject: IdentityId,
        claims: Vec<u8>,
        issued_at: Timestamp,
        expires_at: Option<Timestamp>,
    ) -> Result<Vec<u8>, CredentialError> {
        let payload = SignedPayloadV3 {
            version: CURRENT_VERSION,
            subject,
            issuer,
            issuer_key_id,
            signature_algorithm: CredentialSignatureAlgorithm::Ed25519,
            claims,
            issued_at,
            expires_at,
        };
        let payload_bytes = crate::vault::to_vec(&payload)?;
        let signature = signing_key.sign(&payload_bytes);
        Self::issue_v3(
            CredentialSignatureAlgorithm::Ed25519,
            payload.issuer_key_id,
            payload.issuer,
            payload.subject,
            payload.claims,
            payload.issued_at,
            payload.expires_at,
            signature.to_bytes().to_vec(),
        )
    }

    /// Produces a new ML-DSA-65 credential.
    pub fn issue_ml_dsa65(
        secret_key: &[u8],
        issuer: IdentityId,
        issuer_key_id: KeyId,
        subject: IdentityId,
        claims: Vec<u8>,
        issued_at: Timestamp,
        expires_at: Option<Timestamp>,
    ) -> Result<Vec<u8>, CredentialError> {
        let signing_key = pq_sign::MlDsa65KeyPair::from_secret_key(secret_key)?;
        let payload = SignedPayloadV3 {
            version: CURRENT_VERSION,
            subject,
            issuer,
            issuer_key_id,
            signature_algorithm: CredentialSignatureAlgorithm::MlDsa65,
            claims,
            issued_at,
            expires_at,
        };
        let payload_bytes = crate::vault::to_vec(&payload)?;
        let signature = signing_key.sign(&payload_bytes);
        Self::issue_v3(
            CredentialSignatureAlgorithm::MlDsa65,
            payload.issuer_key_id,
            payload.issuer,
            payload.subject,
            payload.claims,
            payload.issued_at,
            payload.expires_at,
            signature,
        )
    }

    /// Verifies a credential against an Ed25519 verifying key.
    pub fn verify_with_key(
        bytes: &[u8],
        verifying_key: &VerifyingKey,
    ) -> Result<Self, CredentialError> {
        let credential: Credential = crate::vault::from_slice(bytes)?;
        if credential.signature_algorithm != CredentialSignatureAlgorithm::Ed25519 {
            return Err(CredentialError::AlgorithmMismatch);
        }

        match credential.version {
            LEGACY_VERSION => {
                let payload = SignedPayloadV2 {
                    version: credential.version,
                    subject: credential.subject.clone(),
                    issuer: credential.issuer.clone(),
                    issuer_key_id: credential.issuer_key_id.clone(),
                    claims: credential.claims.clone(),
                    issued_at: credential.issued_at,
                    expires_at: credential.expires_at,
                };
                let payload_bytes = crate::vault::to_vec(&payload)?;
                let signature = Signature::from_bytes(&credential.signature)?;
                verifying_key.verify(&payload_bytes, &signature)?;
            }
            CURRENT_VERSION => {
                let payload = SignedPayloadV3 {
                    version: credential.version,
                    subject: credential.subject.clone(),
                    issuer: credential.issuer.clone(),
                    issuer_key_id: credential.issuer_key_id.clone(),
                    signature_algorithm: credential.signature_algorithm,
                    claims: credential.claims.clone(),
                    issued_at: credential.issued_at,
                    expires_at: credential.expires_at,
                };
                let payload_bytes = crate::vault::to_vec(&payload)?;
                let signature = Signature::from_bytes(&credential.signature)?;
                verifying_key.verify(&payload_bytes, &signature)?;
            }
            version => return Err(CredentialError::UnsupportedVersion(version)),
        }

        Ok(credential)
    }

    /// Verifies using the public key bytes named by the credential.
    pub fn verify_with_public_key(
        bytes: &[u8],
        public_key: &[u8],
    ) -> Result<Self, CredentialError> {
        let credential: Credential = crate::vault::from_slice(bytes)?;

        match credential.signature_algorithm {
            CredentialSignatureAlgorithm::Ed25519 => {
                let verifying_key = VerifyingKey::from_bytes(public_key)?;
                Self::verify_with_key(bytes, &verifying_key)
            }
            CredentialSignatureAlgorithm::MlDsa65 => {
                if credential.version != CURRENT_VERSION {
                    return Err(CredentialError::UnsupportedVersion(credential.version));
                }
                let payload = SignedPayloadV3 {
                    version: credential.version,
                    subject: credential.subject.clone(),
                    issuer: credential.issuer.clone(),
                    issuer_key_id: credential.issuer_key_id.clone(),
                    signature_algorithm: credential.signature_algorithm,
                    claims: credential.claims.clone(),
                    issued_at: credential.issued_at,
                    expires_at: credential.expires_at,
                };
                let payload_bytes = crate::vault::to_vec(&payload)?;
                pq_sign::ml_dsa_65_verify(public_key, &payload_bytes, &credential.signature)?;
                Ok(credential)
            }
        }
    }

    #[must_use]
    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }

    #[must_use]
    pub fn claims(&self) -> &[u8] {
        &self.claims
    }

    #[must_use]
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq_sign;
    use crate::crypto::random::OsRandomSource;
    use crate::crypto::sign;

    fn key_id(algorithm: &str) -> KeyId {
        KeyId::generate(&OsRandomSource::new(), algorithm).unwrap()
    }

    fn identity() -> IdentityId {
        IdentityId::generate(&OsRandomSource::new()).unwrap()
    }

    #[test]
    fn ed25519_roundtrip() {
        let pair = sign::generate();
        let bytes = Credential::issue(
            &pair.signing,
            identity(),
            key_id("ed25519"),
            identity(),
            b"role=admin".to_vec(),
            Timestamp::from_secs(1_700_000_000),
            Some(Timestamp::from_secs(1_800_000_000)),
        )
        .unwrap();
        let cred = Credential::verify_with_key(&bytes, &pair.verifying).unwrap();
        assert_eq!(cred.version, CURRENT_VERSION);
        assert_eq!(
            cred.signature_algorithm,
            CredentialSignatureAlgorithm::Ed25519
        );
    }

    #[test]
    fn ml_dsa_roundtrip() {
        let pair = pq_sign::MlDsa65KeyPair::generate();
        let bytes = Credential::issue_ml_dsa65(
            &pair.secret_key(),
            identity(),
            key_id("mldsa65"),
            identity(),
            b"role=pq".to_vec(),
            Timestamp::from_secs(1_700_000_000),
            None,
        )
        .unwrap();
        let cred = Credential::verify_with_public_key(&bytes, &pair.public_key()).unwrap();
        assert_eq!(
            cred.signature_algorithm,
            CredentialSignatureAlgorithm::MlDsa65
        );
    }

    #[test]
    fn algorithm_tampering_is_rejected() {
        let pair = sign::generate();
        let bytes = Credential::issue(
            &pair.signing,
            identity(),
            key_id("ed25519"),
            identity(),
            b"claims".to_vec(),
            Timestamp::from_secs(1_700_000_000),
            None,
        )
        .unwrap();
        let mut cred: Credential = crate::vault::from_slice(&bytes).unwrap();
        cred.signature_algorithm = CredentialSignatureAlgorithm::MlDsa65;
        let tampered = crate::vault::to_vec(&cred).unwrap();
        assert!(matches!(
            Credential::verify_with_key(&tampered, &pair.verifying),
            Err(CredentialError::AlgorithmMismatch)
        ));
    }

    #[test]
    fn expiry_helper_works() {
        let pair = sign::generate();
        let bytes = Credential::issue(
            &pair.signing,
            identity(),
            key_id("ed25519"),
            identity(),
            b"claims".to_vec(),
            Timestamp::from_secs(1_700_000_000),
            Some(Timestamp::from_secs(1_800_000_000)),
        )
        .unwrap();
        let cred = Credential::verify_with_key(&bytes, &pair.verifying).unwrap();
        assert!(!cred.is_expired_at(Timestamp::from_secs(1_700_000_001)));
        assert!(cred.is_expired_at(Timestamp::from_secs(1_900_000_000)));
    }
}

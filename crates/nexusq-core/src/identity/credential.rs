//! Signed credentials.
//!
//! A credential is a statement signed by one identity about another (or
//! about itself). Examples:
//!
//! - "Alice is a member of organization X"
//! - "Bob has completed training course Y"
//! - "Carol is authorized to sign on behalf of the team"
//!
//! NEXUS-Q does not interpret the claims. It signs an opaque byte
//! string and produces a self-contained credential that can be handed
//! to any party that trusts the issuer.
//!
//! ## Lifecycle
//!
//! Credentials are **not stored** in the vault. The issuer produces a
//! CBOR-encoded blob and the caller decides where to keep it. To verify
//! a credential, the verifier needs the issuer's public signing key;
//! the `Session::verify_credential` method resolves it through the
//! vault, and `Credential::verify_with_key` does the pure check without
//! any vault access.
//!
//! ## Signature input
//!
//! The signed bytes are a canonical CBOR encoding of the credential
//! without its `signature` field. Changing any of the other fields
//! invalidates the signature. See ADR 0004.

use serde::{Deserialize, Serialize};

use crate::crypto::sign::{SignError, Signature, SigningKey, VerifyingKey};
use crate::vault::Timestamp;

use super::id::IdentityId;

/// Current credential schema version.
pub const CURRENT_VERSION: u8 = 1;

/// A statement signed by an issuer about a subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// Schema version. Always [`CURRENT_VERSION`] for v1.
    pub version: u8,

    /// The identity the credential is about.
    pub subject: IdentityId,

    /// The identity that issued the credential.
    pub issuer: IdentityId,

    /// Opaque payload. NEXUS-Q signs these bytes without interpreting
    /// them; the format (JSON, CBOR, plain text) is the caller's
    /// concern.
    #[serde(with = "serde_bytes")]
    pub claims: Vec<u8>,

    /// When the credential was issued.
    pub issued_at: Timestamp,

    /// Optional expiration. If present, verifiers should refuse to
    /// accept the credential after this instant.
    pub expires_at: Option<Timestamp>,

    /// The issuer's signature over the credential's canonical form.
    ///
    /// Detached, 64 bytes, produced by Ed25519. Present in the wire
    /// form but excluded from the bytes that are signed.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// The part of a [`Credential`] that is actually signed.
///
/// Kept separate so serialization for signing and serialization for
/// storage do not drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedPayload {
    version: u8,
    subject: IdentityId,
    issuer: IdentityId,
    #[serde(with = "serde_bytes")]
    claims: Vec<u8>,
    issued_at: Timestamp,
    expires_at: Option<Timestamp>,
}

/// Errors returned by credential operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// The credential could not be serialized or deserialized.
    #[error("cbor error: {0}")]
    Cbor(#[from] crate::vault::CborError),

    /// The signature is malformed or does not verify.
    #[error("signature error: {0}")]
    Signature(#[from] SignError),

    /// The credential uses a schema version this build does not know.
    #[error("unsupported credential version: {0}")]
    UnsupportedVersion(u8),

    /// The credential has expired.
    #[error("credential expired")]
    Expired,
}

impl Credential {
    /// Produces a signed credential.
    ///
    /// The resulting bytes are CBOR-encoded and self-contained: any
    /// holder of the issuer's public signing key can verify them.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::Cbor`] if serialization fails.
    pub fn issue(
        signing_key: &SigningKey,
        issuer: IdentityId,
        subject: IdentityId,
        claims: Vec<u8>,
        issued_at: Timestamp,
        expires_at: Option<Timestamp>,
    ) -> Result<Vec<u8>, CredentialError> {
        let payload = SignedPayload {
            version: CURRENT_VERSION,
            subject,
            issuer,
            claims,
            issued_at,
            expires_at,
        };

        let payload_bytes = crate::vault::to_vec(&payload)?;
        let signature = signing_key.sign(&payload_bytes);

        let credential = Credential {
            version: payload.version,
            subject: payload.subject,
            issuer: payload.issuer,
            claims: payload.claims,
            issued_at: payload.issued_at,
            expires_at: payload.expires_at,
            signature: signature.to_bytes().to_vec(),
        };

        Ok(crate::vault::to_vec(&credential)?)
    }

    /// Parses and verifies a credential against an explicit verifying
    /// key.
    ///
    /// Does not consult any vault, does not check expiry. Callers that
    /// need expiry enforcement should check
    /// [`Credential::is_expired_at`].
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::Cbor`] if the input is malformed,
    /// [`CredentialError::UnsupportedVersion`] if the version is not
    /// recognized, or [`CredentialError::Signature`] if the signature
    /// does not verify.
    pub fn verify_with_key(
        bytes: &[u8],
        verifying_key: &VerifyingKey,
    ) -> Result<Self, CredentialError> {
        let credential: Credential = crate::vault::from_slice(bytes)?;

        if credential.version != CURRENT_VERSION {
            return Err(CredentialError::UnsupportedVersion(credential.version));
        }

        // Rebuild the payload that was signed.
        let payload = SignedPayload {
            version: credential.version,
            subject: credential.subject.clone(),
            issuer: credential.issuer.clone(),
            claims: credential.claims.clone(),
            issued_at: credential.issued_at,
            expires_at: credential.expires_at,
        };
        let payload_bytes = crate::vault::to_vec(&payload)?;

        let signature = Signature::from_bytes(&credential.signature)?;
        verifying_key.verify(&payload_bytes, &signature)?;

        Ok(credential)
    }

    /// Returns `true` if the credential has an expiration and `now` is
    /// at or after it.
    #[must_use]
    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        match self.expires_at {
            Some(exp) => now >= exp,
            None => false,
        }
    }

    /// Returns the claims as a byte slice.
    #[must_use]
    pub fn claims(&self) -> &[u8] {
        &self.claims
    }

    /// Returns the signature as a byte slice.
    #[must_use]
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::OsRandomSource;
    use crate::crypto::sign;

    fn sample_id() -> IdentityId {
        let rng = OsRandomSource::new();
        IdentityId::generate(&rng).unwrap()
    }

    fn issue_sample() -> (Vec<u8>, VerifyingKey) {
        let pair = sign::generate();
        let issuer = sample_id();
        let subject = sample_id();
        let claims = b"role=admin".to_vec();
        let issued_at = Timestamp::from_secs(1_700_000_000);
        let expires_at = Some(Timestamp::from_secs(1_800_000_000));

        let bytes = Credential::issue(
            &pair.signing,
            issuer,
            subject,
            claims,
            issued_at,
            expires_at,
        )
        .unwrap();

        (bytes, pair.verifying)
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let (bytes, vk) = issue_sample();
        let cred = Credential::verify_with_key(&bytes, &vk).unwrap();
        assert_eq!(cred.version, CURRENT_VERSION);
        assert_eq!(cred.claims(), b"role=admin");
        assert_eq!(cred.issued_at, Timestamp::from_secs(1_700_000_000));
        assert_eq!(cred.expires_at, Some(Timestamp::from_secs(1_800_000_000)));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (bytes, _vk) = issue_sample();
        let other = sign::generate();
        let err = Credential::verify_with_key(&bytes, &other.verifying).unwrap_err();
        assert!(matches!(err, CredentialError::Signature(_)));
    }

    #[test]
    fn verify_rejects_tampered_claims() {
        let (bytes, vk) = issue_sample();
        let mut cred: Credential = crate::vault::from_slice(&bytes).unwrap();
        cred.claims = b"role=root".to_vec();
        let tampered = crate::vault::to_vec(&cred).unwrap();

        let err = Credential::verify_with_key(&tampered, &vk).unwrap_err();
        assert!(matches!(err, CredentialError::Signature(_)));
    }

    #[test]
    fn verify_rejects_tampered_subject() {
        let (bytes, vk) = issue_sample();
        let mut cred: Credential = crate::vault::from_slice(&bytes).unwrap();
        cred.subject = sample_id();
        let tampered = crate::vault::to_vec(&cred).unwrap();

        let err = Credential::verify_with_key(&tampered, &vk).unwrap_err();
        assert!(matches!(err, CredentialError::Signature(_)));
    }

    #[test]
    fn verify_rejects_tampered_expiry() {
        let (bytes, vk) = issue_sample();
        let mut cred: Credential = crate::vault::from_slice(&bytes).unwrap();
        cred.expires_at = Some(Timestamp::from_secs(9_999_999_999));
        let tampered = crate::vault::to_vec(&cred).unwrap();

        let err = Credential::verify_with_key(&tampered, &vk).unwrap_err();
        assert!(matches!(err, CredentialError::Signature(_)));
    }

    #[test]
    fn verify_rejects_unsupported_version() {
        let (bytes, vk) = issue_sample();
        let mut cred: Credential = crate::vault::from_slice(&bytes).unwrap();
        cred.version = 99;
        let tampered = crate::vault::to_vec(&cred).unwrap();

        let err = Credential::verify_with_key(&tampered, &vk).unwrap_err();
        assert!(matches!(err, CredentialError::UnsupportedVersion(99)));
    }

    #[test]
    fn expiry_helper_works() {
        let (bytes, vk) = issue_sample();
        let cred = Credential::verify_with_key(&bytes, &vk).unwrap();

        let before = Timestamp::from_secs(1_700_000_001);
        let after = Timestamp::from_secs(1_900_000_000);
        assert!(!cred.is_expired_at(before));
        assert!(cred.is_expired_at(after));
    }

    #[test]
    fn credential_without_expiry_never_expires() {
        let pair = sign::generate();
        let issuer = sample_id();
        let subject = sample_id();
        let bytes = Credential::issue(
            &pair.signing,
            issuer,
            subject,
            b"permanent".to_vec(),
            Timestamp::from_secs(1_700_000_000),
            None,
        )
        .unwrap();
        let cred = Credential::verify_with_key(&bytes, &pair.verifying).unwrap();
        assert!(!cred.is_expired_at(Timestamp::from_secs(u64::MAX - 1)));
    }
}

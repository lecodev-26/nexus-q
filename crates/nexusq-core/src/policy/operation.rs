//! Policy operations.
//!
//! A [`PolicyOperation`] names the action a policy governs. The set is
//! closed: adding an operation is a deliberate change that requires a
//! new match arm in the evaluator, so a policy can never silently
//! cover an action the evaluator does not understand.
//!
//! See `docs/SECURITY_MODEL.md` §5.2.

use serde::{Deserialize, Serialize};

/// An action that a policy can allow, deny, or leave undecided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyOperation {
    // --- Key lifecycle ---
    /// Create a new key.
    KeyCreate,
    /// Activate a generated key.
    KeyActivate,
    /// Rotate an active key.
    KeyRotate,
    /// Revoke a key.
    KeyRevoke,
    /// Destroy a key irreversibly.
    KeyDestroy,

    // --- Key usage ---
    /// Use a key to sign.
    Sign,
    /// Use a key to verify a signature. Rarely policy-controlled.
    Verify,
    /// Use a key to encrypt.
    Encrypt,
    /// Use a key to decrypt.
    Decrypt,
    /// Use a key for key agreement (KEM).
    KeyAgreement,
    /// Use a key to wrap another key.
    Wrap,

    // --- Identity ---
    /// Create a new identity.
    IdentityCreate,
    /// Sign a message on behalf of an identity.
    IdentitySign,
    /// Rotate an identity's signing key.
    IdentityRotateKey,
    /// Revoke an identity.
    IdentityRevoke,

    // --- Credentials ---
    /// Issue a credential.
    CredentialIssue,
    /// Verify a credential.
    CredentialVerify,
    /// Revoke an individual credential.
    CredentialRevoke,

    // --- Envelope ---
    /// Seal an envelope (in-memory or file).
    EnvelopeSeal,
    /// Open an envelope (in-memory or file).
    EnvelopeOpen,
}

impl PolicyOperation {
    /// Returns the canonical lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyCreate => "key_create",
            Self::KeyActivate => "key_activate",
            Self::KeyRotate => "key_rotate",
            Self::KeyRevoke => "key_revoke",
            Self::KeyDestroy => "key_destroy",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::KeyAgreement => "key_agreement",
            Self::Wrap => "wrap",
            Self::IdentityCreate => "identity_create",
            Self::IdentitySign => "identity_sign",
            Self::IdentityRotateKey => "identity_rotate_key",
            Self::IdentityRevoke => "identity_revoke",
            Self::CredentialIssue => "credential_issue",
            Self::CredentialVerify => "credential_verify",
            Self::CredentialRevoke => "credential_revoke",
            Self::EnvelopeSeal => "envelope_seal",
            Self::EnvelopeOpen => "envelope_open",
        }
    }

    /// Returns `true` if the operation works on a specific key.
    ///
    /// Operations that target a key are matched against
    /// [`PolicyTarget::Key`](super::PolicyTarget::Key); others match
    /// against broader targets.
    #[must_use]
    pub const fn targets_key(self) -> bool {
        matches!(
            self,
            Self::KeyActivate
                | Self::KeyRotate
                | Self::KeyRevoke
                | Self::KeyDestroy
                | Self::Sign
                | Self::Verify
                | Self::Encrypt
                | Self::Decrypt
                | Self::KeyAgreement
                | Self::Wrap
                | Self::EnvelopeSeal
                | Self::EnvelopeOpen
        )
    }

    /// Returns `true` if the operation works on a specific identity.
    #[must_use]
    pub const fn targets_identity(self) -> bool {
        matches!(
            self,
            Self::IdentitySign
                | Self::IdentityRotateKey
                | Self::IdentityRevoke
                | Self::CredentialIssue
                | Self::CredentialVerify
                | Self::CredentialRevoke
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_strings_are_stable() {
        assert_eq!(PolicyOperation::KeyCreate.as_str(), "key_create");
        assert_eq!(PolicyOperation::KeyActivate.as_str(), "key_activate");
        assert_eq!(PolicyOperation::KeyRotate.as_str(), "key_rotate");
        assert_eq!(PolicyOperation::KeyRevoke.as_str(), "key_revoke");
        assert_eq!(PolicyOperation::KeyDestroy.as_str(), "key_destroy");
        assert_eq!(PolicyOperation::Sign.as_str(), "sign");
        assert_eq!(PolicyOperation::Verify.as_str(), "verify");
        assert_eq!(PolicyOperation::Encrypt.as_str(), "encrypt");
        assert_eq!(PolicyOperation::Decrypt.as_str(), "decrypt");
        assert_eq!(PolicyOperation::KeyAgreement.as_str(), "key_agreement");
        assert_eq!(PolicyOperation::Wrap.as_str(), "wrap");
        assert_eq!(PolicyOperation::IdentityCreate.as_str(), "identity_create");
        assert_eq!(PolicyOperation::IdentitySign.as_str(), "identity_sign");
        assert_eq!(
            PolicyOperation::IdentityRotateKey.as_str(),
            "identity_rotate_key"
        );
        assert_eq!(PolicyOperation::IdentityRevoke.as_str(), "identity_revoke");
        assert_eq!(
            PolicyOperation::CredentialIssue.as_str(),
            "credential_issue"
        );
        assert_eq!(
            PolicyOperation::CredentialVerify.as_str(),
            "credential_verify"
        );
        assert_eq!(
            PolicyOperation::CredentialRevoke.as_str(),
            "credential_revoke"
        );
        assert_eq!(PolicyOperation::EnvelopeSeal.as_str(), "envelope_seal");
        assert_eq!(PolicyOperation::EnvelopeOpen.as_str(), "envelope_open");
    }

    #[test]
    fn key_targeting_operations_are_marked() {
        assert!(PolicyOperation::Sign.targets_key());
        assert!(PolicyOperation::Decrypt.targets_key());
        assert!(PolicyOperation::KeyRotate.targets_key());
        assert!(!PolicyOperation::KeyCreate.targets_key());
        assert!(!PolicyOperation::IdentityCreate.targets_key());
    }

    #[test]
    fn identity_targeting_operations_are_marked() {
        assert!(PolicyOperation::IdentitySign.targets_identity());
        assert!(PolicyOperation::IdentityRevoke.targets_identity());
        assert!(PolicyOperation::CredentialIssue.targets_identity());
        assert!(PolicyOperation::CredentialVerify.targets_identity());
        assert!(PolicyOperation::CredentialRevoke.targets_identity());
        assert!(!PolicyOperation::Sign.targets_identity());
        assert!(!PolicyOperation::KeyCreate.targets_identity());
    }

    #[test]
    fn operations_roundtrip_through_cbor() {
        for op in [
            PolicyOperation::KeyCreate,
            PolicyOperation::Sign,
            PolicyOperation::IdentitySign,
            PolicyOperation::CredentialIssue,
            PolicyOperation::EnvelopeSeal,
        ] {
            let bytes = crate::vault::to_vec(&op).unwrap();
            let back: PolicyOperation = crate::vault::from_slice(&bytes).unwrap();
            assert_eq!(back, op);
        }
    }
}

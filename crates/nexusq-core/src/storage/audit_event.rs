//! Audit events.
//!
//! An audit event is a security-relevant record: a key was created,
//! a vault was unlocked, a policy changed. Events never contain
//! secret material, and they are chained so that a past entry cannot
//! be modified without detection.
//!
//! ## Chaining
//!
//! Every event carries the hash of the previous event in the same
//! segment. The hash of event `n` is:
//!
//! ```text
//! hash_n = SHA-256( canonical_bytes(body_n) || prev_hash_n )
//! ```
//!
//! where `body_n` is the event with the `hash` and `prev_hash` fields
//! removed, and `canonical_bytes` is CBOR encoding with deterministic
//! field order.
//!
//! Modifying any field of any past event changes its hash, which
//! breaks the `prev_hash` link of the next event, and so on to the
//! end of the chain. A verifier only needs the first event and the
//! hash chain to detect tampering.
//!
//! See `docs/SECURITY_MODEL.md` §7 and `docs/STORAGE.md` §7.

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha256;
use crate::vault::Timestamp;

use super::db::DbError;

/// Length in bytes of the hash carried by every event.
pub const HASH_LEN: usize = 32;

/// A chain of zeros, used as the `prev_hash` of the first event in a
/// segment.
pub const GENESIS_HASH: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// The kind of event being recorded.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    // --- Key lifecycle ---
    /// A key was created.
    KeyCreated,
    /// A key was activated.
    KeyActivated,
    /// A key was used for a cryptographic operation.
    KeyUsed,
    /// A key was rotated.
    KeyRotated,
    /// A key was revoked.
    KeyRevoked,
    /// A key was destroyed.
    KeyDestroyed,
    /// A key was exported.
    KeyExported,
    /// An operation was refused by policy.
    KeyAccessDenied,

    // --- Identity lifecycle ---
    /// An identity was created.
    IdentityCreated,
    /// An identity's signing key was rotated.
    IdentityKeyRotated,
    /// An identity was revoked.
    IdentityRevoked,
    /// An identity produced a signature.
    IdentitySigned,

    // --- Credentials ---
    /// A credential was issued.
    CredentialIssued,
    /// A credential was verified.
    CredentialVerified,

    // --- Envelope ---
    /// An envelope was sealed (data encrypted).
    EnvelopeSealed,
    /// An envelope was opened (data decrypted).
    EnvelopeOpened,

    // --- Backup ---
    /// A backup was exported.
    BackupExported,
    /// A backup was imported.
    BackupImported,

    // --- Vault lifecycle ---
    /// A vault was created.
    VaultCreated,
    /// A vault was unlocked.
    VaultUnlocked,
    /// A vault was locked.
    VaultLocked,
    /// A vault was sealed.
    VaultSealed,

    // --- Audit log ---
    /// The audit log configuration was changed.
    AuditConfigured,

    // --- Session and policy ---
    /// A session ended.
    SessionEnded,
    /// A policy was changed.
    PolicyChanged,
    /// A format migration was performed.
    MigrationPerformed,
    /// Any other event, with a free-form tag.
    Other(String),
}

impl EventType {
    /// Returns the canonical lowercase identifier.
    ///
    /// For [`EventType::Other`], returns the embedded tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            // Key lifecycle
            Self::KeyCreated => "key_created",
            Self::KeyActivated => "key_activated",
            Self::KeyUsed => "key_used",
            Self::KeyRotated => "key_rotated",
            Self::KeyRevoked => "key_revoked",
            Self::KeyDestroyed => "key_destroyed",
            Self::KeyExported => "key_exported",
            Self::KeyAccessDenied => "key_access_denied",

            // Identity lifecycle
            Self::IdentityCreated => "identity_created",
            Self::IdentityKeyRotated => "identity_key_rotated",
            Self::IdentityRevoked => "identity_revoked",
            Self::IdentitySigned => "identity_signed",

            // Credentials
            Self::CredentialIssued => "credential_issued",
            Self::CredentialVerified => "credential_verified",

            // Envelope
            Self::EnvelopeSealed => "envelope_sealed",
            Self::EnvelopeOpened => "envelope_opened",

            // Backup
            Self::BackupExported => "backup_exported",
            Self::BackupImported => "backup_imported",

            // Vault lifecycle
            Self::VaultCreated => "vault_created",
            Self::VaultUnlocked => "vault_unlocked",
            Self::VaultLocked => "vault_locked",
            Self::VaultSealed => "vault_sealed",

            // Audit log
            Self::AuditConfigured => "audit_configured",

            // Session and policy
            Self::SessionEnded => "session_ended",
            Self::PolicyChanged => "policy_changed",
            Self::MigrationPerformed => "migration_performed",
            Self::Other(tag) => tag,
        }
    }
}

/// Whether the operation described by an event succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventOutcome {
    /// The operation completed as requested.
    Success,
    /// The operation failed for a reason other than policy.
    Failure,
    /// The operation was refused by policy.
    Denied,
}

impl EventOutcome {
    /// Returns the canonical lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

/// The part of an event that is hashed.
///
/// Kept separate from [`AuditEvent`] so that serialization for hashing
/// and serialization for storage cannot drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AuditEventBody {
    index: u64,
    timestamp: Timestamp,
    event_type: EventType,
    actor: String,
    subject: String,
    outcome: EventOutcome,
    #[serde(with = "serde_bytes")]
    context: Vec<u8>,
}

/// One security-relevant record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic index within the segment, starting at 1.
    pub index: u64,

    /// When the event happened.
    pub timestamp: Timestamp,

    /// What happened.
    pub event_type: EventType,

    /// Who or what triggered it.
    pub actor: String,

    /// What it was about (a KeyId, a VaultId, an identity).
    pub subject: String,

    /// Whether the operation succeeded.
    pub outcome: EventOutcome,

    /// Minimal, non-secret context.
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,

    /// Hash of the previous event in the chain, or
    /// [`GENESIS_HASH`] for the first.
    #[serde(with = "serde_bytes")]
    pub prev_hash: Vec<u8>,

    /// Hash of this event: `SHA-256(canonical(body) || prev_hash)`.
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

/// The fields of an event that are chosen by the caller.
///
/// Grouped so that [`AuditEvent::new`] stays readable as the number
/// of fields grows, and so that callers can build a specification
/// once and reuse it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventSpec {
    /// What happened.
    pub event_type: EventType,
    /// Who or what triggered it.
    pub actor: String,
    /// What it was about.
    pub subject: String,
    /// Whether the operation succeeded.
    pub outcome: EventOutcome,
    /// Minimal, non-secret context.
    pub context: Vec<u8>,
}

impl AuditEventSpec {
    /// Creates a specification with the given type and defaults.
    #[must_use]
    pub fn new(event_type: EventType) -> Self {
        Self {
            event_type,
            actor: String::new(),
            subject: String::new(),
            outcome: EventOutcome::Success,
            context: Vec::new(),
        }
    }

    /// Sets the actor.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }

    /// Sets the subject.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    /// Sets the outcome.
    #[must_use]
    pub fn with_outcome(mut self, outcome: EventOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Sets the context.
    #[must_use]
    pub fn with_context(mut self, context: Vec<u8>) -> Self {
        self.context = context;
        self
    }
}

impl AuditEvent {
    /// Creates and hashes a new event.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::MalformedRecord`] if `prev_hash` is not
    /// exactly [`HASH_LEN`] bytes or if CBOR serialization of the body
    /// fails.
    pub fn new(
        index: u64,
        timestamp: Timestamp,
        spec: AuditEventSpec,
        prev_hash: &[u8],
    ) -> Result<Self, DbError> {
        if prev_hash.len() != HASH_LEN {
            return Err(DbError::MalformedRecord);
        }

        let body = AuditEventBody {
            index,
            timestamp,
            event_type: spec.event_type,
            actor: spec.actor,
            subject: spec.subject,
            outcome: spec.outcome,
            context: spec.context,
        };

        let body_bytes = canonical_body_bytes(&body)?;
        let mut to_hash = Vec::with_capacity(body_bytes.len() + HASH_LEN);
        to_hash.extend_from_slice(&body_bytes);
        to_hash.extend_from_slice(prev_hash);
        let hash = sha256(&to_hash).to_vec();

        Ok(Self {
            index: body.index,
            timestamp: body.timestamp,
            event_type: body.event_type,
            actor: body.actor,
            subject: body.subject,
            outcome: body.outcome,
            context: body.context,
            prev_hash: prev_hash.to_vec(),
            hash,
        })
    }

    /// Recomputes the hash from the event's fields and returns it.
    ///
    /// Used by verification. A mismatch between this value and the
    /// stored `hash` field means the event was modified.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::MalformedRecord`] if CBOR serialization
    /// fails or the stored `prev_hash` has the wrong length.
    pub fn recompute_hash(&self) -> Result<Vec<u8>, DbError> {
        if self.prev_hash.len() != HASH_LEN {
            return Err(DbError::MalformedRecord);
        }
        let body = AuditEventBody {
            index: self.index,
            timestamp: self.timestamp,
            event_type: self.event_type.clone(),
            actor: self.actor.clone(),
            subject: self.subject.clone(),
            outcome: self.outcome,
            context: self.context.clone(),
        };
        let body_bytes = canonical_body_bytes(&body)?;
        let mut to_hash = Vec::with_capacity(body_bytes.len() + HASH_LEN);
        to_hash.extend_from_slice(&body_bytes);
        to_hash.extend_from_slice(&self.prev_hash);
        Ok(sha256(&to_hash).to_vec())
    }

    /// Returns `true` if the stored hash matches a fresh computation.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::MalformedRecord`] if the hash cannot be
    /// recomputed (see [`AuditEvent::recompute_hash`]).
    pub fn is_intact(&self) -> Result<bool, DbError> {
        let computed = self.recompute_hash()?;
        Ok(computed == self.hash)
    }
}

fn canonical_body_bytes(body: &AuditEventBody) -> Result<Vec<u8>, DbError> {
    crate::vault::to_vec(body).map_err(|_| DbError::MalformedRecord)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(index: u64, event_type: EventType, prev: &[u8]) -> Result<AuditEvent, DbError> {
        let spec = AuditEventSpec::new(event_type)
            .with_actor("test-actor")
            .with_subject("test-subject")
            .with_context(b"context".to_vec());
        AuditEvent::new(
            index,
            Timestamp::from_secs(1_700_000_000 + index),
            spec,
            prev,
        )
    }

    #[test]
    fn event_type_strings_are_stable() {
        // Key lifecycle
        assert_eq!(EventType::KeyCreated.as_str(), "key_created");
        assert_eq!(EventType::KeyActivated.as_str(), "key_activated");
        assert_eq!(EventType::KeyUsed.as_str(), "key_used");
        assert_eq!(EventType::KeyRotated.as_str(), "key_rotated");
        assert_eq!(EventType::KeyRevoked.as_str(), "key_revoked");
        assert_eq!(EventType::KeyDestroyed.as_str(), "key_destroyed");
        assert_eq!(EventType::KeyExported.as_str(), "key_exported");
        assert_eq!(EventType::KeyAccessDenied.as_str(), "key_access_denied");

        // Identity
        assert_eq!(EventType::IdentityCreated.as_str(), "identity_created");
        assert_eq!(
            EventType::IdentityKeyRotated.as_str(),
            "identity_key_rotated"
        );
        assert_eq!(EventType::IdentityRevoked.as_str(), "identity_revoked");
        assert_eq!(EventType::IdentitySigned.as_str(), "identity_signed");

        // Credentials
        assert_eq!(EventType::CredentialIssued.as_str(), "credential_issued");
        assert_eq!(
            EventType::CredentialVerified.as_str(),
            "credential_verified"
        );

        // Envelope
        assert_eq!(EventType::EnvelopeSealed.as_str(), "envelope_sealed");
        assert_eq!(EventType::EnvelopeOpened.as_str(), "envelope_opened");

        // Backup
        assert_eq!(EventType::BackupExported.as_str(), "backup_exported");
        assert_eq!(EventType::BackupImported.as_str(), "backup_imported");

        // Vault and policy
        assert_eq!(EventType::VaultCreated.as_str(), "vault_created");
        assert_eq!(EventType::VaultUnlocked.as_str(), "vault_unlocked");
        assert_eq!(EventType::PolicyChanged.as_str(), "policy_changed");
        assert_eq!(EventType::Other("custom".into()).as_str(), "custom");
    }

    #[test]
    fn event_outcome_strings_are_stable() {
        assert_eq!(EventOutcome::Success.as_str(), "success");
        assert_eq!(EventOutcome::Failure.as_str(), "failure");
        assert_eq!(EventOutcome::Denied.as_str(), "denied");
    }

    #[test]
    fn new_event_has_hash_of_expected_length() {
        let e = make(1, EventType::KeyCreated, &GENESIS_HASH).unwrap();
        assert_eq!(e.hash.len(), HASH_LEN);
        assert_eq!(e.prev_hash.len(), HASH_LEN);
    }

    #[test]
    fn new_event_with_wrong_prev_hash_length_fails() {
        let spec = AuditEventSpec::new(EventType::VaultCreated);
        let err = AuditEvent::new(1, Timestamp::from_secs(0), spec, b"short");
        assert!(matches!(err, Err(DbError::MalformedRecord)));
    }

    #[test]
    fn event_is_intact_right_after_creation() {
        let e = make(1, EventType::KeyCreated, &GENESIS_HASH).unwrap();
        assert!(e.is_intact().unwrap());
    }

    #[test]
    fn modifying_index_breaks_the_hash() {
        let mut e = make(1, EventType::KeyCreated, &GENESIS_HASH).unwrap();
        e.index = 2;
        assert!(!e.is_intact().unwrap());
    }

    #[test]
    fn modifying_event_type_breaks_the_hash() {
        let mut e = make(1, EventType::KeyCreated, &GENESIS_HASH).unwrap();
        e.event_type = EventType::KeyDestroyed;
        assert!(!e.is_intact().unwrap());
    }

    #[test]
    fn modifying_actor_breaks_the_hash() {
        let mut e = make(1, EventType::KeyCreated, &GENESIS_HASH).unwrap();
        e.actor = "someone-else".into();
        assert!(!e.is_intact().unwrap());
    }

    #[test]
    fn modifying_context_breaks_the_hash() {
        let mut e = make(1, EventType::KeyCreated, &GENESIS_HASH).unwrap();
        e.context = b"different".to_vec();
        assert!(!e.is_intact().unwrap());
    }

    #[test]
    fn modifying_prev_hash_breaks_the_hash() {
        let mut e = make(1, EventType::KeyCreated, &GENESIS_HASH).unwrap();
        e.prev_hash = vec![0xAA; HASH_LEN];
        assert!(!e.is_intact().unwrap());
    }

    #[test]
    fn different_prev_hash_produces_different_event_hash() {
        let a = make(1, EventType::KeyCreated, &GENESIS_HASH).unwrap();
        let prev = [0xAA; HASH_LEN];
        let b = make(1, EventType::KeyCreated, &prev).unwrap();
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn events_roundtrip_through_cbor() {
        let e = make(1, EventType::KeyCreated, &GENESIS_HASH).unwrap();
        let bytes = crate::vault::to_vec(&e).unwrap();
        let back: AuditEvent = crate::vault::from_slice(&bytes).unwrap();
        assert_eq!(back, e);
        assert!(back.is_intact().unwrap());
    }

    #[test]
    fn spec_builder_sets_all_fields() {
        let spec = AuditEventSpec::new(EventType::KeyCreated)
            .with_actor("alice")
            .with_subject("nqk_test")
            .with_outcome(EventOutcome::Denied)
            .with_context(b"info".to_vec());
        assert_eq!(spec.event_type, EventType::KeyCreated);
        assert_eq!(spec.actor, "alice");
        assert_eq!(spec.subject, "nqk_test");
        assert_eq!(spec.outcome, EventOutcome::Denied);
        assert_eq!(spec.context, b"info");
    }
}

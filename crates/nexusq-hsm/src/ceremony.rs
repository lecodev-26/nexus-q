//! Quorum-authorized ceremonies for generating CA keys in an HSM.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use getrandom::fill;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{HsmKeyStore, Pkcs11KeyRef};

const CEREMONY_DOMAIN: &[u8] = b"NEXUSQ-HSM-KEY-CEREMONY-v1\0";
const MAX_CEREMONY_EVENTS: usize = 10_000;

/// Operations that can be authorized by a quorum. Key generation is deliberately explicit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyAction {
    GenerateMlDsa65CaKey,
    DestroyMlDsa65CaKey,
}

/// Participant allowed to approve key ceremonies. The private approval key stays with the custodian.
#[derive(Clone, Debug)]
pub struct CeremonyParticipant {
    pub id: String,
    pub public_key: [u8; 32],
}

/// Public ceremony transcript distributed to custodians for independent approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyRequest {
    pub id: String,
    pub action: CeremonyAction,
    pub key_label: String,
    pub nonce: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub target_key: Option<Pkcs11KeyRef>,
}
impl CeremonyRequest {
    /// Canonical, domain-separated bytes that each custodian must sign with their own approval key.
    pub fn approval_payload(&self) -> Vec<u8> {
        let mut out = CEREMONY_DOMAIN.to_vec();
        append_field(&mut out, self.id.as_bytes());
        out.push(match self.action {
            CeremonyAction::GenerateMlDsa65CaKey => 1,
            CeremonyAction::DestroyMlDsa65CaKey => 2,
        });
        append_field(&mut out, self.key_label.as_bytes());
        append_field(&mut out, &self.nonce);
        if let Some(key) = &self.target_key {
            append_field(&mut out, key.key_id());
            append_field(&mut out, key.token_serial().as_bytes());
            append_field(&mut out, key.public_key_bytes());
        } else {
            append_field(&mut out, &[]);
        }
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }
}
fn append_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&(field.len() as u32).to_be_bytes());
    output.extend_from_slice(field);
}

/// Observable lifecycle of a key ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyStatus {
    Pending,
    Approved,
    Executing,
    Completed,
    Expired,
}
struct CeremonyRecord {
    request: CeremonyRequest,
    approvals: HashSet<String>,
    status: CeremonyStatus,
    executing: bool,
    key: Option<Pkcs11KeyRef>,
}

/// Public audit event for a ceremony transition; it never contains approvals or private key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyAuditEvent {
    pub ceremony_id: String,
    pub event: String,
    pub participant_id: Option<String>,
    pub key_label: String,
    pub approval_count: usize,
    pub timestamp: u64,
    pub transcript_sha256: String,
}

/// Errors from quorum verification and ceremony state transitions.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("invalid M-of-N threshold or participant set")]
    InvalidPolicy,
    #[error("unknown ceremony")]
    NotFound,
    #[error("ceremony request does not match the recorded transcript")]
    TranscriptMismatch,
    #[error("unknown custodian")]
    UnknownParticipant,
    #[error("custodian approval signature is invalid")]
    InvalidSignature,
    #[error("custodian has already approved this ceremony")]
    DuplicateApproval,
    #[error("approval threshold has not been met")]
    ThresholdNotMet,
    #[error("ceremony has expired")]
    Expired,
    #[error("ceremony is already executing")]
    InProgress,
    #[error("ceremony has already completed")]
    AlreadyFinalized,
    #[error("ceremony action does not match the requested finalization operation")]
    WrongAction,
    #[error("HSM key operation failed: {0}")]
    Hsm(String),
    #[error("secure random generation failed")]
    Randomness,
    #[error("ceremony state is unavailable")]
    StateUnavailable,
}

/// In-memory M-of-N approval coordinator. HSM private keys are generated only after quorum approval.
pub struct CeremonyCoordinator {
    hsm: Arc<dyn HsmKeyStore>,
    participants: HashMap<String, VerifyingKey>,
    threshold: usize,
    ttl: Duration,
    ceremonies: Mutex<HashMap<String, CeremonyRecord>>,
    events: Mutex<Vec<CeremonyAuditEvent>>,
}
impl CeremonyCoordinator {
    /// Configure an M-of-N policy. Ceremony TTL must be between 60 seconds and 24 hours.
    pub fn new(
        hsm: Arc<dyn HsmKeyStore>,
        participants: Vec<CeremonyParticipant>,
        threshold: usize,
        ttl: Duration,
    ) -> Result<Self, CeremonyError> {
        if participants.is_empty()
            || threshold == 0
            || threshold > participants.len()
            || ttl < Duration::from_secs(60)
            || ttl > Duration::from_secs(24 * 60 * 60)
        {
            return Err(CeremonyError::InvalidPolicy);
        }
        let mut parsed = HashMap::new();
        for participant in participants {
            if participant.id.is_empty()
                || participant.id.len() > 128
                || participant.id.chars().any(char::is_control)
            {
                return Err(CeremonyError::InvalidPolicy);
            }
            let key = VerifyingKey::from_bytes(&participant.public_key)
                .map_err(|_| CeremonyError::InvalidPolicy)?;
            if parsed.insert(participant.id, key).is_some() {
                return Err(CeremonyError::InvalidPolicy);
            }
        }
        Ok(Self {
            hsm,
            participants: parsed,
            threshold,
            ttl,
            ceremonies: Mutex::new(HashMap::new()),
            events: Mutex::new(Vec::new()),
        })
    }

    /// Start a key-generation ceremony; this does not create any HSM object yet.
    pub fn start_key_generation(
        &self,
        key_label: impl Into<String>,
    ) -> Result<CeremonyRequest, CeremonyError> {
        self.start_request(CeremonyAction::GenerateMlDsa65CaKey, key_label.into(), None)
    }

    /// Start a quorum-controlled key-destruction ceremony for an existing token key.
    pub fn start_key_destruction(
        &self,
        key: &Pkcs11KeyRef,
    ) -> Result<CeremonyRequest, CeremonyError> {
        self.start_request(
            CeremonyAction::DestroyMlDsa65CaKey,
            key.label().to_owned(),
            Some(key.clone()),
        )
    }

    fn start_request(
        &self,
        action: CeremonyAction,
        key_label: String,
        target_key: Option<Pkcs11KeyRef>,
    ) -> Result<CeremonyRequest, CeremonyError> {
        if key_label.is_empty()
            || key_label.len() > 64
            || !key_label.is_ascii()
            || key_label.chars().any(char::is_control)
        {
            return Err(CeremonyError::InvalidPolicy);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CeremonyError::Randomness)?
            .as_secs();
        let expires_at = now
            .checked_add(self.ttl.as_secs())
            .ok_or(CeremonyError::Randomness)?;
        let mut id_bytes = [0u8; 16];
        let mut nonce = [0u8; 32];
        fill(&mut id_bytes).map_err(|_| CeremonyError::Randomness)?;
        fill(&mut nonce).map_err(|_| CeremonyError::Randomness)?;
        let id = id_bytes.iter().fold(
            String::with_capacity(id_bytes.len() * 2),
            |mut output, byte| {
                let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"));
                output
            },
        );
        let request = CeremonyRequest {
            id: id.clone(),
            action,
            key_label,
            nonce: nonce.to_vec(),
            created_at: now,
            expires_at,
            target_key,
        };
        self.ceremonies
            .lock()
            .map_err(|_| CeremonyError::StateUnavailable)?
            .insert(
                id,
                CeremonyRecord {
                    request: request.clone(),
                    approvals: HashSet::new(),
                    status: CeremonyStatus::Pending,
                    executing: false,
                    key: None,
                },
            );
        self.record_event(&request, "started", None, 0);
        Ok(request)
    }

    /// Verify and record a custodian's Ed25519 approval over the exact public transcript.
    pub fn approve(
        &self,
        request: &CeremonyRequest,
        participant_id: &str,
        signature_bytes: &[u8],
    ) -> Result<usize, CeremonyError> {
        let mut ceremonies = self
            .ceremonies
            .lock()
            .map_err(|_| CeremonyError::StateUnavailable)?;
        let record = ceremonies
            .get_mut(&request.id)
            .ok_or(CeremonyError::NotFound)?;
        if record.request != *request {
            return Err(CeremonyError::TranscriptMismatch);
        }
        if unix_now() >= request.expires_at {
            record.status = CeremonyStatus::Expired;
            return Err(CeremonyError::Expired);
        }
        if record.key.is_some() {
            return Err(CeremonyError::AlreadyFinalized);
        }
        if record.executing {
            return Err(CeremonyError::InProgress);
        }
        let participant = self
            .participants
            .get(participant_id)
            .ok_or(CeremonyError::UnknownParticipant)?;
        if record.approvals.contains(participant_id) {
            return Err(CeremonyError::DuplicateApproval);
        }
        let signature =
            Signature::from_slice(signature_bytes).map_err(|_| CeremonyError::InvalidSignature)?;
        participant
            .verify(&request.approval_payload(), &signature)
            .map_err(|_| CeremonyError::InvalidSignature)?;
        record.approvals.insert(participant_id.to_owned());
        record.status = if record.approvals.len() >= self.threshold {
            CeremonyStatus::Approved
        } else {
            CeremonyStatus::Pending
        };
        let count = record.approvals.len();
        let request = record.request.clone();
        drop(ceremonies);
        self.record_event(&request, "approval_accepted", Some(participant_id), count);
        Ok(count)
    }

    /// Execute the HSM key-generation operation exactly once after the configured quorum approves.
    pub fn finalize(&self, ceremony_id: &str) -> Result<Pkcs11KeyRef, CeremonyError> {
        let request = {
            let mut ceremonies = self
                .ceremonies
                .lock()
                .map_err(|_| CeremonyError::StateUnavailable)?;
            let record = ceremonies
                .get_mut(ceremony_id)
                .ok_or(CeremonyError::NotFound)?;
            if record.key.is_some() {
                return Err(CeremonyError::AlreadyFinalized);
            }
            if record.request.action != CeremonyAction::GenerateMlDsa65CaKey {
                return Err(CeremonyError::WrongAction);
            }
            if record.executing {
                return Err(CeremonyError::InProgress);
            }
            if unix_now() >= record.request.expires_at {
                record.status = CeremonyStatus::Expired;
                return Err(CeremonyError::Expired);
            }
            if record.approvals.len() < self.threshold {
                return Err(CeremonyError::ThresholdNotMet);
            }
            record.executing = true;
            record.status = CeremonyStatus::Executing;
            record.request.clone()
        };
        let result = self.hsm.generate_mldsa65_ca_key(&request.key_label);
        let mut ceremonies = self
            .ceremonies
            .lock()
            .map_err(|_| CeremonyError::StateUnavailable)?;
        let record = ceremonies
            .get_mut(ceremony_id)
            .ok_or(CeremonyError::NotFound)?;
        record.executing = false;
        match result {
            Ok(key) => {
                record.key = Some(key.clone());
                record.status = CeremonyStatus::Completed;
                let request = record.request.clone();
                let count = record.approvals.len();
                drop(ceremonies);
                self.record_event(&request, "completed", None, count);
                Ok(key)
            }
            Err(error) => {
                record.status = CeremonyStatus::Approved;
                let request = record.request.clone();
                let count = record.approvals.len();
                drop(ceremonies);
                self.record_event(&request, "hsm_generation_failed", None, count);
                Err(CeremonyError::Hsm(error.to_string()))
            }
        }
    }

    /// Destroy a token key only after the destruction transcript has reached quorum.
    pub fn finalize_destruction(&self, ceremony_id: &str) -> Result<(), CeremonyError> {
        let (request, key) = {
            let mut ceremonies = self
                .ceremonies
                .lock()
                .map_err(|_| CeremonyError::StateUnavailable)?;
            let record = ceremonies
                .get_mut(ceremony_id)
                .ok_or(CeremonyError::NotFound)?;
            if record.key.is_some() {
                return Err(CeremonyError::AlreadyFinalized);
            }
            if record.request.action != CeremonyAction::DestroyMlDsa65CaKey {
                return Err(CeremonyError::WrongAction);
            }
            if record.executing {
                return Err(CeremonyError::InProgress);
            }
            if unix_now() >= record.request.expires_at {
                record.status = CeremonyStatus::Expired;
                return Err(CeremonyError::Expired);
            }
            if record.approvals.len() < self.threshold {
                return Err(CeremonyError::ThresholdNotMet);
            }
            let key = record
                .request
                .target_key
                .clone()
                .ok_or(CeremonyError::TranscriptMismatch)?;
            record.executing = true;
            record.status = CeremonyStatus::Executing;
            (record.request.clone(), key)
        };
        let result = self.hsm.destroy_key(&key);
        let mut ceremonies = self
            .ceremonies
            .lock()
            .map_err(|_| CeremonyError::StateUnavailable)?;
        let record = ceremonies
            .get_mut(ceremony_id)
            .ok_or(CeremonyError::NotFound)?;
        record.executing = false;
        match result {
            Ok(()) => {
                record.key = Some(key);
                record.status = CeremonyStatus::Completed;
                let count = record.approvals.len();
                drop(ceremonies);
                self.record_event(&request, "destroyed", None, count);
                Ok(())
            }
            Err(error) => {
                record.status = CeremonyStatus::Approved;
                let count = record.approvals.len();
                drop(ceremonies);
                self.record_event(&request, "hsm_destruction_failed", None, count);
                Err(CeremonyError::Hsm(error.to_string()))
            }
        }
    }

    fn record_event(
        &self,
        request: &CeremonyRequest,
        event: &str,
        participant_id: Option<&str>,
        approval_count: usize,
    ) {
        let digest = Sha256::digest(request.approval_payload());
        let transcript_sha256 = digest.iter().fold(
            String::with_capacity(digest.len() * 2),
            |mut output, byte| {
                let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"));
                output
            },
        );
        let item = CeremonyAuditEvent {
            ceremony_id: request.id.clone(),
            event: event.to_owned(),
            participant_id: participant_id.map(str::to_owned),
            key_label: request.key_label.clone(),
            approval_count,
            timestamp: unix_now(),
            transcript_sha256,
        };
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if events.len() >= MAX_CEREMONY_EVENTS {
            events.remove(0);
        }
        events.push(item);
    }

    /// Snapshot the in-memory ceremony audit events for forwarding to a durable audit sink.
    pub fn audit_events(&self) -> Vec<CeremonyAuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Return ceremony status and the number of distinct approvals received.
    pub fn status(&self, ceremony_id: &str) -> Result<(CeremonyStatus, usize), CeremonyError> {
        let ceremonies = self
            .ceremonies
            .lock()
            .map_err(|_| CeremonyError::StateUnavailable)?;
        let record = ceremonies.get(ceremony_id).ok_or(CeremonyError::NotFound)?;
        Ok((record.status, record.approvals.len()))
    }
}
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HsmError;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeHsm {
        generated: AtomicUsize,
        destroyed: AtomicUsize,
    }
    impl HsmKeyStore for FakeHsm {
        fn generate_mldsa65_ca_key(&self, label: &str) -> Result<Pkcs11KeyRef, HsmError> {
            self.generated.fetch_add(1, Ordering::SeqCst);
            Ok(Pkcs11KeyRef::from_parts(
                vec![1, 2, 3],
                label.to_owned(),
                "test-token".to_owned(),
                vec![4, 5, 6],
            ))
        }
        fn destroy_key(&self, _key: &Pkcs11KeyRef) -> Result<(), HsmError> {
            self.destroyed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn m_of_n_requires_distinct_valid_approvals_and_executes_once() {
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32]].map(|bytes| SigningKey::from_bytes(&bytes));
        let participants = keys
            .iter()
            .enumerate()
            .map(|(index, key)| CeremonyParticipant {
                id: format!("custodian-{index}"),
                public_key: key.verifying_key().to_bytes(),
            })
            .collect();
        let hsm = Arc::new(FakeHsm {
            generated: AtomicUsize::new(0),
            destroyed: AtomicUsize::new(0),
        });
        let coordinator =
            CeremonyCoordinator::new(hsm.clone(), participants, 2, Duration::from_secs(300))
                .unwrap();
        let request = coordinator.start_key_generation("nexusq-test-ca").unwrap();
        assert!(matches!(
            coordinator.finalize(&request.id),
            Err(CeremonyError::ThresholdNotMet)
        ));
        let payload = request.approval_payload();
        let signature = keys[0].sign(&payload).to_bytes();
        assert_eq!(
            coordinator
                .approve(&request, "custodian-0", &signature)
                .unwrap(),
            1
        );
        assert!(matches!(
            coordinator.approve(&request, "custodian-0", &signature),
            Err(CeremonyError::DuplicateApproval)
        ));
        assert!(matches!(
            coordinator.finalize(&request.id),
            Err(CeremonyError::ThresholdNotMet)
        ));
        let signature = keys[1].sign(&payload).to_bytes();
        assert_eq!(
            coordinator
                .approve(&request, "custodian-1", &signature)
                .unwrap(),
            2
        );
        let key = coordinator.finalize(&request.id).unwrap();
        assert_eq!(key.label(), "nexusq-test-ca");
        assert_eq!(
            coordinator.status(&request.id).unwrap(),
            (CeremonyStatus::Completed, 2)
        );
        assert!(matches!(
            coordinator.finalize(&request.id),
            Err(CeremonyError::AlreadyFinalized)
        ));
        assert_eq!(hsm.generated.load(Ordering::SeqCst), 1);
        let events = coordinator.audit_events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event == "approval_accepted")
                .count(),
            2
        );
        assert_eq!(events.last().unwrap().event, "completed");
        let destroy_request = coordinator.start_key_destruction(&key).unwrap();
        assert!(matches!(
            coordinator.finalize_destruction(&destroy_request.id),
            Err(CeremonyError::ThresholdNotMet)
        ));
        for (index, key) in keys.iter().enumerate().take(2) {
            let signature = key.sign(&destroy_request.approval_payload()).to_bytes();
            coordinator
                .approve(&destroy_request, &format!("custodian-{index}"), &signature)
                .unwrap();
        }
        coordinator
            .finalize_destruction(&destroy_request.id)
            .unwrap();
        assert_eq!(hsm.destroyed.load(Ordering::SeqCst), 1);
        assert_eq!(
            coordinator.audit_events().last().unwrap().event,
            "destroyed"
        );
    }

    #[test]
    fn invalid_signature_does_not_count_toward_quorum() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let participant = CeremonyParticipant {
            id: "custodian".to_owned(),
            public_key: key.verifying_key().to_bytes(),
        };
        let hsm = Arc::new(FakeHsm {
            generated: AtomicUsize::new(0),
            destroyed: AtomicUsize::new(0),
        });
        let coordinator =
            CeremonyCoordinator::new(hsm, vec![participant], 1, Duration::from_secs(300)).unwrap();
        let request = coordinator.start_key_generation("test-ca").unwrap();
        assert!(matches!(
            coordinator.approve(&request, "custodian", &[0u8; 64]),
            Err(CeremonyError::InvalidSignature)
        ));
        assert_eq!(
            coordinator.status(&request.id).unwrap(),
            (CeremonyStatus::Pending, 0)
        );
    }
}

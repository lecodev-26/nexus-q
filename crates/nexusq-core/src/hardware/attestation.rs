//! Attestation.
//!
//! An [`AttestationProvider`] lets the device prove which software it
//! is running. In software the only honest answer is "I cannot prove
//! anything"; the trait exists so that hardware backends can offer
//! real attestation without changing the call sites.
//!
//! See `docs/ARCHITECTURE.md` §6.4.

use super::HardwareError;

/// Cryptographic digest of a measured component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    /// Name of the component (e.g., "bootloader", "nexusq-core").
    pub component: String,
    /// Digest of the component, in the backend's preferred algorithm.
    pub digest: Vec<u8>,
}

/// An attestation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationReport {
    /// Measurements included in the report.
    pub measurements: Vec<Measurement>,
    /// Nonce echoed back from the request, if one was supplied.
    pub nonce: Option<Vec<u8>>,
    /// Backend-specific signature over the report, if any.
    pub signature: Option<Vec<u8>>,
}

/// Operations for measuring and attesting.
pub trait AttestationProvider: Send + Sync {
    /// Returns whether this backend can produce attestation reports.
    fn is_available(&self) -> bool;

    /// Measures a component, returning its digest.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotSupported`] if the backend cannot
    /// measure components, or another hardware error if measurement
    /// fails.
    fn measure(&self, component: &str) -> Result<Measurement, HardwareError>;

    /// Produces an attestation report over the given nonce.
    ///
    /// The nonce, if present, must be echoed back in the report so the
    /// verifier can bind it to a live challenge.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareError::NotSupported`] if the backend cannot
    /// attest, or another hardware error if the operation fails.
    fn attest(&self, nonce: Option<&[u8]>) -> Result<AttestationReport, HardwareError>;
}

/// What a verifier expects from a report.
///
/// A report can be cryptographically valid and still be useless if it
/// is stale, missing a component the verifier cares about, or was
/// produced for a different challenge. The policy expresses those
/// expectations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttestationPolicy {
    /// The nonce the verifier sent in its challenge. If present, the
    /// report must echo it back unchanged.
    pub expected_nonce: Option<Vec<u8>>,

    /// Names of components that must appear in the report. If a name
    /// is missing, verification fails.
    pub required_components: Vec<String>,
}

impl AttestationPolicy {
    /// Creates an empty policy: only structural checks apply.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the expected nonce.
    #[must_use]
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.expected_nonce = Some(nonce);
        self
    }

    /// Adds a required component.
    #[must_use]
    pub fn requiring(mut self, component: impl Into<String>) -> Self {
        self.required_components.push(component.into());
        self
    }
}

/// Errors returned by attestation verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// The report does not have the expected shape: missing fields,
    /// empty measurements, or a signature that is present but empty.
    #[error("malformed attestation report")]
    MalformedReport,

    /// The report's nonce does not match the challenge.
    #[error("nonce mismatch")]
    NonceMismatch,

    /// A component required by the policy is absent.
    #[error("missing required component: {0}")]
    MissingComponent(String),

    /// The signature over the report is invalid.
    #[error("invalid attestation signature")]
    SignatureInvalid,

    /// The verifier cannot check this kind of report.
    #[error("attestation verification not supported")]
    NotSupported,
}

/// Structural checks that do not depend on a backend.
///
/// A report must:
///
/// - have at least one measurement;
/// - have every measurement with a non-empty component name and a
///   non-empty digest;
/// - if a signature is present, it must not be empty.
///
/// This function does **not** verify the signature. That requires the
/// backend's root of trust and is the job of a concrete
/// [`AttestationVerifier`].
///
/// # Errors
///
/// Returns [`AttestationError::MalformedReport`] if any of the checks
/// above fail.
pub fn verify_report_structure(report: &AttestationReport) -> Result<(), AttestationError> {
    if report.measurements.is_empty() {
        return Err(AttestationError::MalformedReport);
    }
    for m in &report.measurements {
        if m.component.is_empty() || m.digest.is_empty() {
            return Err(AttestationError::MalformedReport);
        }
    }
    if let Some(sig) = &report.signature {
        if sig.is_empty() {
            return Err(AttestationError::MalformedReport);
        }
    }
    Ok(())
}

/// Checks a report against a policy.
///
/// Applies the structural checks from [`verify_report_structure`],
/// then:
///
/// - if `policy.expected_nonce` is `Some`, the report must carry the
///   same nonce;
/// - every component in `policy.required_components` must be present
///   among the report's measurements.
///
/// This function does **not** verify the signature. A backend that
/// trusts a root of trust should implement [`AttestationVerifier`]
/// and call this helper from its own verification.
///
/// # Errors
///
/// Returns the corresponding [`AttestationError`] for the first check
/// that fails.
pub fn verify_report_against_policy(
    report: &AttestationReport,
    policy: &AttestationPolicy,
) -> Result<(), AttestationError> {
    verify_report_structure(report)?;

    if let Some(expected) = &policy.expected_nonce {
        match &report.nonce {
            Some(got) if got == expected => {}
            _ => return Err(AttestationError::NonceMismatch),
        }
    }

    for required in &policy.required_components {
        let present = report.measurements.iter().any(|m| &m.component == required);
        if !present {
            return Err(AttestationError::MissingComponent(required.clone()));
        }
    }

    Ok(())
}

/// A backend that can verify attestation reports.
///
/// A concrete implementation knows the root of trust of the reports
/// it accepts and can check the signature. It should call
/// [`verify_report_against_policy`] for the parts that do not need
/// the root of trust, then add its own cryptographic check.
pub trait AttestationVerifier: Send + Sync {
    /// Verifies `report` against `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError`] describing the first failed check.
    fn verify(
        &self,
        report: &AttestationReport,
        policy: &AttestationPolicy,
    ) -> Result<(), AttestationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> AttestationReport {
        AttestationReport {
            measurements: vec![
                Measurement {
                    component: "bootloader".into(),
                    digest: vec![0xAA; 32],
                },
                Measurement {
                    component: "kernel".into(),
                    digest: vec![0xBB; 32],
                },
            ],
            nonce: Some(b"challenge-42".to_vec()),
            signature: Some(vec![0xCC; 64]),
        }
    }

    #[test]
    fn structural_check_accepts_well_formed_report() {
        assert!(verify_report_structure(&sample_report()).is_ok());
    }

    #[test]
    fn structural_check_rejects_empty_measurements() {
        let report = AttestationReport {
            measurements: vec![],
            nonce: None,
            signature: None,
        };
        assert!(matches!(
            verify_report_structure(&report),
            Err(AttestationError::MalformedReport)
        ));
    }

    #[test]
    fn structural_check_rejects_measurement_with_empty_name() {
        let report = AttestationReport {
            measurements: vec![Measurement {
                component: "".into(),
                digest: vec![0xAA; 32],
            }],
            nonce: None,
            signature: None,
        };
        assert!(matches!(
            verify_report_structure(&report),
            Err(AttestationError::MalformedReport)
        ));
    }

    #[test]
    fn structural_check_rejects_measurement_with_empty_digest() {
        let report = AttestationReport {
            measurements: vec![Measurement {
                component: "kernel".into(),
                digest: vec![],
            }],
            nonce: None,
            signature: None,
        };
        assert!(matches!(
            verify_report_structure(&report),
            Err(AttestationError::MalformedReport)
        ));
    }

    #[test]
    fn structural_check_rejects_empty_signature() {
        let mut report = sample_report();
        report.signature = Some(vec![]);
        assert!(matches!(
            verify_report_structure(&report),
            Err(AttestationError::MalformedReport)
        ));
    }

    #[test]
    fn policy_with_matching_nonce_passes() {
        let report = sample_report();
        let policy = AttestationPolicy::new().with_nonce(b"challenge-42".to_vec());
        assert!(verify_report_against_policy(&report, &policy).is_ok());
    }

    #[test]
    fn policy_with_mismatched_nonce_fails() {
        let report = sample_report();
        let policy = AttestationPolicy::new().with_nonce(b"other".to_vec());
        assert!(matches!(
            verify_report_against_policy(&report, &policy),
            Err(AttestationError::NonceMismatch)
        ));
    }

    #[test]
    fn policy_requiring_absent_component_fails() {
        let report = sample_report();
        let policy = AttestationPolicy::new().requiring("nexusq");
        assert!(matches!(
            verify_report_against_policy(&report, &policy),
            Err(AttestationError::MissingComponent(_))
        ));
    }

    #[test]
    fn policy_requiring_present_component_passes() {
        let report = sample_report();
        let policy = AttestationPolicy::new()
            .requiring("bootloader")
            .requiring("kernel");
        assert!(verify_report_against_policy(&report, &policy).is_ok());
    }

    #[test]
    fn empty_policy_only_checks_structure() {
        let report = sample_report();
        let policy = AttestationPolicy::new();
        assert!(verify_report_against_policy(&report, &policy).is_ok());
    }

    #[test]
    fn policy_rejects_report_without_nonce_when_nonce_expected() {
        let mut report = sample_report();
        report.nonce = None;
        let policy = AttestationPolicy::new().with_nonce(b"challenge-42".to_vec());
        assert!(matches!(
            verify_report_against_policy(&report, &policy),
            Err(AttestationError::NonceMismatch)
        ));
    }

    #[test]
    fn error_strings_are_stable() {
        assert_eq!(
            AttestationError::MalformedReport.to_string(),
            "malformed attestation report"
        );
        assert_eq!(
            AttestationError::NonceMismatch.to_string(),
            "nonce mismatch"
        );
        assert_eq!(
            AttestationError::MissingComponent("kernel".into()).to_string(),
            "missing required component: kernel"
        );
        assert_eq!(
            AttestationError::SignatureInvalid.to_string(),
            "invalid attestation signature"
        );
        assert_eq!(
            AttestationError::NotSupported.to_string(),
            "attestation verification not supported"
        );
    }
}

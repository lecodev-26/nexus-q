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

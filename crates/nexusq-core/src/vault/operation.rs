//! Cooperative cancellation and truthful progress reporting for vault operations.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A coarse backend phase. Phases are not percentages; callers should show an
/// indeterminate indicator unless a concrete completed/total pair is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum OperationPhase {
    Preparing,
    ReadingInput,
    Processing,
    WritingOutput,
    Verifying,
    Completed,
}

/// A progress update emitted by the operation that is doing the work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationProgress {
    pub phase: OperationPhase,
    /// Completed units, when the backend can measure them accurately.
    pub completed: Option<u64>,
    /// Total units, when the backend can measure them accurately.
    pub total: Option<u64>,
}

impl OperationProgress {
    #[must_use]
    pub const fn phase(phase: OperationPhase) -> Self {
        Self {
            phase,
            completed: None,
            total: None,
        }
    }

    #[must_use]
    pub const fn measured(phase: OperationPhase, completed: u64, total: u64) -> Self {
        Self {
            phase,
            completed: Some(completed),
            total: Some(total),
        }
    }
}

/// Cloneable cancellation handle. Cancellation is observed only at documented
/// safe points; it never interrupts an in-progress cryptographic primitive.
#[derive(Debug, Clone, Default)]
pub struct OperationControl(Arc<AtomicBool>);

impl OperationControl {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. The operation will stop at its next safe point.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Return an error when cancellation has been requested.
    pub fn check_cancelled(&self) -> Result<(), OperationCancelled> {
        if self.is_cancelled() {
            Err(OperationCancelled)
        } else {
            Ok(())
        }
    }
}

/// Returned when an operation reaches a safe point after cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("operation cancelled")]
pub struct OperationCancelled;

/// Distinguishes cooperative cancellation from an operation failure.
#[derive(Debug, thiserror::Error)]
pub enum OperationError<E> {
    #[error("operation cancelled")]
    Cancelled(OperationCancelled),
    #[error(transparent)]
    Failed(E),
}

impl<E> From<E> for OperationError<E> {
    fn from(error: E) -> Self {
        Self::Failed(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloned_control_shares_cancellation_request() {
        let control = OperationControl::new();
        let worker = control.clone();
        assert!(!worker.is_cancelled());
        control.cancel();
        assert!(worker.is_cancelled());
        assert_eq!(worker.check_cancelled(), Err(OperationCancelled));
    }

    #[test]
    fn phase_progress_does_not_invent_a_percentage() {
        let progress = OperationProgress::phase(OperationPhase::Processing);
        assert_eq!(progress.completed, None);
        assert_eq!(progress.total, None);
    }
}

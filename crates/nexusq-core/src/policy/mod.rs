//! Access control and security policy.
//!
//! The policy engine decides whether an operation is allowed. It is
//! separate from authentication: authentication says who the caller
//! is, policy says what they may do.
//!
//! ## Default deny
//!
//! A session with no policies refuses every operation. Rules must be
//! added explicitly, and each rule must name a target and (usually)
//! at least one condition. See `docs/SECURITY_MODEL.md` §5.2.
//!
//! ## Status
//!
//! Fase 11 has landed the type layer: operations, targets,
//! conditions, contexts and decisions. The evaluator
//! (`PolicySet::evaluate`) and the session integration arrive in the
//! next sub-phases.

pub mod condition;
pub mod context;
pub mod decision;
pub mod error;
pub mod operation;
pub mod target;

pub use condition::PolicyCondition;
pub use context::PolicyContext;
pub use decision::PolicyDecision;
pub use error::PolicyError;
pub use operation::PolicyOperation;
pub use target::PolicyTarget;

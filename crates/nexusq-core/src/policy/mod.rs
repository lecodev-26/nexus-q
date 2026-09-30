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
//! ## Structure
//!
//! A [`PolicySet`] is an ordered list of [`Policy`] rules. Evaluation
//! walks the list once: the first rule that applies with a Deny
//! effect wins immediately; otherwise the first applying Allow is
//! returned; if no rule applies, the decision is
//! [`PolicyDecision::NoDecision`], which callers treat as a refusal.
//!
//! ## Status
//!
//! Fase 11 has landed the type layer and the evaluator. The
//! integration with `Session` and persistence in the vault body
//! arrive in the next sub-phases.

pub mod condition;
pub mod context;
pub mod decision;
pub mod error;
pub mod operation;
pub mod rule;
pub mod set;
pub mod target;

pub use condition::PolicyCondition;
pub use context::PolicyContext;
pub use decision::PolicyDecision;
pub use error::PolicyError;
pub use operation::PolicyOperation;
pub use rule::{Policy, PolicyEffect};
pub use set::PolicySet;
pub use target::PolicyTarget;

//! `nexusq` — one dependency for the complete NEXUS-Q Rust library stack.
//!
//! NEXUS-Q is a post-quantum cryptographic security engine for protecting
//! data, keys and identities. The functionality lives in focused, separately
//! versioned crates published to crates.io:
//!
//! - [`nexusq_core`] — the core library (vault, identity, policy, crypto).
//! - [`nexusq_kernels`] — portable scalar reference kernels and dispatch.
//! - [`nexusq_ml_kem`] — ML-KEM (FIPS 203) key encapsulation.
//! - [`nexusq_ml_dsa`] — ML-DSA (FIPS 204) signatures.
//!
//! This metacrate exists so that a single
//!
//! ```text
//! cargo add nexusq
//! ```
//!
//! adds all of them to your project. It re-exports each component crate as a
//! module and provides a [`prelude`] with the most used types, so you can
//! start with:
//!
//! ```
//! use nexusq::prelude::*;
//! ```
//!
//! Prefer minimal dependency trees? Add the individual crates instead — for
//! example `cargo add nexusq-core`. The CLI (`cargo install nexusq-cli`) and
//! the server (`cargo install nexusq-server`) are separate binary crates and
//! are not pulled in by this metacrate.

pub use nexusq_core;
pub use nexusq_kernels;
pub use nexusq_ml_dsa;
pub use nexusq_ml_kem;

/// Common imports, mirroring [`nexusq_core::prelude`].
pub mod prelude {
    pub use nexusq_core::prelude::*;
}

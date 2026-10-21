//! NEXUS-Q core library.
//!
//! Post-quantum cryptographic engine for protecting data, keys, and
//! identities. This crate is the library that every other component
//! (CLI, server, SDKs) builds on top of.
//!
//! # Getting started
//!
//! The quickest way to pull in the public types is:
//!
//! ```
//! use nexusq_core::prelude::*;
//! ```
//!
//! That brings in the error type, the vault and session types, the
//! identity types, the policy types and the most used crypto
//! primitives. Everything else is reachable through the module tree.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod hardware;
pub mod identity;
pub mod observability;
pub mod policy;
pub mod storage;
pub mod vault;

pub use error::{Error, Result};
pub use observability::{Metrics, OBSERVABILITY_SCHEMA_VERSION};

/// Build-time cryptographic backend selected for ML-KEM and ML-DSA.
///
/// This reports the compiled provider; it is not a runtime selector. The
/// native provider is experimental and must be explicitly enabled with the
/// `native-backend` Cargo feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendInfo {
    /// Stable machine-readable provider identifier.
    pub name: &'static str,
    /// Whether the selected provider is experimental and unaudited.
    pub experimental: bool,
    /// Whether native backend support was compiled into this build.
    pub native_available: bool,
}

/// Describes the cryptographic provider compiled into this build.
///
/// RustCrypto remains the default. Enabling `native-backend` selects the
/// experimental native implementation at compile time; it does not provide
/// a runtime fallback or change the provider of an already-built binary.
pub const fn backend_info() -> BackendInfo {
    #[cfg(feature = "native-backend")]
    {
        BackendInfo {
            name: "native-experimental",
            experimental: true,
            native_available: true,
        }
    }
    #[cfg(not(feature = "native-backend"))]
    {
        BackendInfo {
            name: "rustcrypto",
            experimental: false,
            native_available: false,
        }
    }
}

/// Common imports.
///
/// Bringing this module into scope provides the types most callers
/// need: the unified error, the vault and session, the key and
/// identity identifiers, the policy layer, the audit log, and the
/// random source trait.
///
/// It deliberately does not re-export everything. The full API is
/// reachable through the module tree; this is a curated subset.
pub mod prelude {
    pub use crate::error::{Error, Result};

    pub use crate::crypto::CryptoError;
    pub use crate::hardware::HardwareError;
    pub use crate::identity::IdentityError;
    pub use crate::policy::PolicyError;
    pub use crate::storage::StorageError;

    pub use crate::vault::{
        Algorithm, KeyId, KeyMetadata, KeyRecord, KeyStatus, Purpose, Session, Timestamp, Vault,
        VaultError, WrappedKeyMaterial,
    };

    pub use crate::identity::{Credential, Identity, IdentityId, IdentityStatus};

    pub use crate::policy::{
        Policy, PolicyCondition, PolicyDecision, PolicyEffect, PolicyOperation, PolicySet,
        PolicyTarget,
    };

    pub use crate::storage::{AuditEvent, AuditLog, EventType};

    pub use crate::crypto::random::{OsRandomSource, RandomSource};

    pub use crate::hardware::SoftwareBackend;
}

#[cfg(test)]
mod backend_info_tests {
    use super::backend_info;

    #[test]
    fn reports_the_compiled_provider_consistently() {
        let info = backend_info();
        #[cfg(feature = "native-backend")]
        assert_eq!(
            (info.name, info.experimental, info.native_available),
            ("native-experimental", true, true)
        );
        #[cfg(not(feature = "native-backend"))]
        assert_eq!(
            (info.name, info.experimental, info.native_available),
            ("rustcrypto", false, false)
        );
    }
}

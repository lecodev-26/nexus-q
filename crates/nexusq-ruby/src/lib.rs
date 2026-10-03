//! Ruby bindings for NEXUS-Q via UniFFI.
//!
//! This crate exposes a small subset of the library through a UDL
//! file (see `src/nexusq.udl`) that UniFFI uses to generate Ruby
//! bindings.

uniffi::include_scaffolding!("nexusq");

use nexusq_core::vault;

/// Returns the library version.
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Errors surfaced to Ruby callers.
#[derive(Debug, thiserror::Error)]
pub enum NexusqError {
    #[error("invalid input")]
    InvalidInput,
    #[error("operation failed")]
    Operation,
}

/// A vault file on disk.
pub struct Vault {
    path: String,
    format_version: u8,
}

impl Vault {
    /// Creates a new vault at `path` with the given password.
    fn new_from_path(
        path: String,
        password: String,
        label: Option<String>,
    ) -> Result<Self, NexusqError> {
        let vault = vault::Vault::create(&path, password.as_bytes(), label)
            .map_err(|_| NexusqError::Operation)?;
        Ok(Self {
            path: vault.path().display().to_string(),
            format_version: vault.header().version,
        })
    }

    /// Returns the path of the vault file.
    fn path(&self) -> String {
        self.path.clone()
    }

    /// Returns the format version of the vault file.
    fn format_version(&self) -> u8 {
        self.format_version
    }
}

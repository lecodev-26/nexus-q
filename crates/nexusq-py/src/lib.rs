//! Python bindings for NEXUS-Q.
//!
//! This crate exposes the library through PyO3. It is a thin
//! translation layer that delegates directly to `nexusq-core` and
//! marshals results and errors into Python objects. No
//! cryptography and no business logic live here.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Returns the library version.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// A vault file on disk.
#[pyclass]
struct Vault {
    path: String,
    format_version: u8,
}

#[pymethods]
impl Vault {
    /// Creates a new vault at `path` with the given password.
    ///
    /// An optional `label` is stored in the vault metadata.
    #[staticmethod]
    #[pyo3(signature = (path, password, label=None))]
    fn create(path: &str, password: &str, label: Option<&str>) -> PyResult<Self> {
        let vault =
            nexusq_core::vault::Vault::create(path, password.as_bytes(), label.map(String::from))
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            path: vault.path().display().to_string(),
            format_version: vault.header().version,
        })
    }

    /// Returns the path of the vault file.
    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    /// Returns the format version of the vault file.
    #[getter]
    fn format_version(&self) -> u8 {
        self.format_version
    }

    fn __repr__(&self) -> String {
        format!(
            "Vault(path={:?}, format_version={})",
            self.path, self.format_version
        )
    }
}

/// Python module definition.
#[pymodule]
fn nexusq(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_class::<Vault>()?;
    Ok(())
}

//! Runtime backend selection for cryptographic kernels.
//!
//! Selection is resolved once and cached. Until an optimized backend has passed
//! differential and security gates, the portable scalar implementation remains
//! the only selectable backend on every architecture.

use std::sync::OnceLock;

/// Kernel backend selected for this process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    /// Portable reference implementation; currently the only implemented backend.
    Scalar,
}

/// Why the dispatcher selected its backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionReason {
    /// The caller requested the portable implementation via environment or feature.
    ForcedScalar,
    /// No optimized backend is currently enabled and eligible for selection.
    NoOptimizedBackendAvailable,
}

/// CPU capabilities useful when deciding which optimized kernels may be enabled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuFeatures {
    /// x86 AVX2 instruction set is available to this process.
    pub avx2: bool,
    /// x86 AVX-512 Foundation instruction set is available to this process.
    pub avx512f: bool,
    /// x86 BMI2 instruction set is available to this process.
    pub bmi2: bool,
    /// AArch64 NEON/Advanced SIMD is available (mandatory on AArch64 targets).
    pub neon: bool,
    /// AArch64 SHA-3 instructions are available.
    pub arm_sha3: bool,
}

/// Immutable dispatch decision, resolved once per process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchInfo {
    /// Selected implementation.
    pub backend: Backend,
    /// Reason the selected implementation was chosen.
    pub reason: SelectionReason,
    /// Runtime CPU capabilities; these do not imply an optimized backend exists.
    pub cpu: CpuFeatures,
}

static DISPATCH_INFO: OnceLock<DispatchInfo> = OnceLock::new();

/// Return the cached backend decision for this process.
///
/// Set `NEXUSQ_FORCE_SCALAR=1` (also accepts `true`, `yes`, or `on`) to make the
/// scalar preference explicit. The `force-scalar` Cargo feature provides a
/// compile-time equivalent. Scalar is currently selected either way because no
/// optimized kernel backend has passed the project's correctness/security gates.
pub fn dispatch_info() -> &'static DispatchInfo {
    DISPATCH_INFO.get_or_init(resolve_dispatch)
}

/// Return the selected backend without requiring callers to inspect dispatch metadata.
#[inline]
pub fn selected_backend() -> Backend {
    dispatch_info().backend
}

fn resolve_dispatch() -> DispatchInfo {
    let forced = cfg!(feature = "force-scalar")
        || std::env::var("NEXUSQ_FORCE_SCALAR")
            .ok()
            .is_some_and(|value| is_truthy(&value));

    DispatchInfo {
        backend: Backend::Scalar,
        reason: if forced {
            SelectionReason::ForcedScalar
        } else {
            SelectionReason::NoOptimizedBackendAvailable
        },
        cpu: detect_cpu_features(),
    }
}

fn is_truthy(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

fn detect_cpu_features() -> CpuFeatures {
    let mut features = CpuFeatures::default();

    #[cfg(target_arch = "x86_64")]
    {
        features.avx2 = std::is_x86_feature_detected!("avx2");
        features.avx512f = std::is_x86_feature_detected!("avx512f");
        features.bmi2 = std::is_x86_feature_detected!("bmi2");
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Advanced SIMD is mandatory in the AArch64 execution environment.
        features.neon = true;
        features.arm_sha3 = std::arch::is_aarch64_feature_detected!("sha3");
    }

    features
}

#[cfg(test)]
mod tests {
    use super::{Backend, dispatch_info, is_truthy, selected_backend};

    #[test]
    fn force_scalar_parser_accepts_common_truthy_values() {
        for value in ["1", "true", "TRUE", " yes ", "On"] {
            assert!(is_truthy(value), "expected {value:?} to be truthy");
        }
    }

    #[test]
    fn force_scalar_parser_rejects_other_values() {
        for value in ["", "0", "false", "no", "off", "maybe"] {
            assert!(!is_truthy(value), "expected {value:?} to be false");
        }
    }

    #[test]
    fn dispatcher_uses_the_safe_scalar_fallback_until_optimized_kernels_exist() {
        assert_eq!(selected_backend(), Backend::Scalar);
        assert_eq!(dispatch_info().backend, Backend::Scalar);
    }

    #[test]
    fn dispatch_decision_is_cached() {
        assert!(std::ptr::eq(dispatch_info(), dispatch_info()));
    }
}

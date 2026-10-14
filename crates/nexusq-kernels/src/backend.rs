//! Stable internal contract shared by scalar and future optimized kernels.
//!
//! Implementations must preserve the scalar backend's exact output semantics.
//! An implementation must not be selected by runtime dispatch until differential
//! tests and the security/performance gates in `docs/V3_V4_ROADMAP.md` pass.

use crate::scalar::{keccak, mlkem};

/// Kernel operations that every backend must implement with bit-exact semantics.
///
/// This contract deliberately contains only primitive operations with existing
/// scalar reference implementations. Higher-level algorithms should build on
/// these primitives instead of duplicating backend selection logic.
pub trait KernelBackend {
    /// Apply the `Keccak-f\[1600\]` permutation to a 25-lane state.
    fn keccak_f1600(state: &mut [u64; 25]);

    /// Compute SHAKE128 into a caller-provided output buffer.
    fn shake128(input: &[u8], output: &mut [u8]);

    /// Compute SHAKE256 into a caller-provided output buffer.
    fn shake256(input: &[u8], output: &mut [u8]);

    /// Apply the ML-KEM number-theoretic transform in place.
    fn ntt(poly: &mut mlkem::Polynomial);

    /// Apply the inverse ML-KEM number-theoretic transform in place.
    fn inverse_ntt(poly: &mut mlkem::Polynomial);

    /// Multiply two ML-KEM polynomials using the base multiplication routine.
    fn basemul(lhs: &mlkem::Polynomial, rhs: &mlkem::Polynomial) -> mlkem::Polynomial;

    /// Reduce an integer into the backend's canonical modular range.
    fn reduce(value: i32) -> i16;

    /// Freeze an integer into its canonical representative.
    fn freeze(value: i32) -> i16;
}

/// Portable reference backend. It is the only implemented backend for now.
///
/// This wrapper does not claim constant-time behavior; the scalar ML-KEM code
/// remains a correctness/reference implementation and is not production-ready.
pub struct ScalarBackend;

impl KernelBackend for ScalarBackend {
    #[inline]
    fn keccak_f1600(state: &mut [u64; 25]) {
        keccak::keccak_f1600(state);
    }

    #[inline]
    fn shake128(input: &[u8], output: &mut [u8]) {
        keccak::shake128(input, output);
    }

    #[inline]
    fn shake256(input: &[u8], output: &mut [u8]) {
        keccak::shake256(input, output);
    }

    #[inline]
    fn ntt(poly: &mut mlkem::Polynomial) {
        mlkem::ntt(poly);
    }

    #[inline]
    fn inverse_ntt(poly: &mut mlkem::Polynomial) {
        mlkem::inverse_ntt(poly);
    }

    #[inline]
    fn basemul(lhs: &mlkem::Polynomial, rhs: &mlkem::Polynomial) -> mlkem::Polynomial {
        mlkem::basemul(lhs, rhs)
    }

    #[inline]
    fn reduce(value: i32) -> i16 {
        mlkem::reduce(value)
    }

    #[inline]
    fn freeze(value: i32) -> i16 {
        mlkem::freeze(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{KernelBackend, ScalarBackend};
    use crate::scalar::{keccak, mlkem};

    #[test]
    fn scalar_backend_matches_reference_for_keccak_and_shake() {
        let mut direct = [0_u64; 25];
        let mut through_backend = direct;
        keccak::keccak_f1600(&mut direct);
        ScalarBackend::keccak_f1600(&mut through_backend);
        assert_eq!(through_backend, direct);

        let input = b"nexus-q backend contract";
        let mut expected = [0_u8; 64];
        let mut actual = [0_u8; 64];
        keccak::shake256(input, &mut expected);
        ScalarBackend::shake256(input, &mut actual);
        assert_eq!(actual, expected);
    }

    #[test]
    fn scalar_backend_matches_reference_for_mlkem_primitives() {
        let mut direct = [0_i16; mlkem::N];
        let mut through_backend = direct;
        mlkem::ntt(&mut direct);
        ScalarBackend::ntt(&mut through_backend);
        assert_eq!(through_backend, direct);
        assert_eq!(ScalarBackend::reduce(-17), mlkem::reduce(-17));
        assert_eq!(
            ScalarBackend::freeze(mlkem::Q as i32 + 3),
            mlkem::freeze(mlkem::Q as i32 + 3)
        );
    }
}

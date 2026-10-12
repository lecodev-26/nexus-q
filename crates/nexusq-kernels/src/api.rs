//! Backend-routed entry points for primitive cryptographic kernels.
//!
//! Callers should use this module when they want the crate's dispatch policy to
//! choose an implementation. The current policy routes every operation to the
//! scalar reference backend; optimized implementations remain gated by Issue #23.

use crate::backend::{KernelBackend, ScalarBackend};
use crate::dispatch::{Backend, selected_backend};
use crate::scalar::mlkem::Polynomial;

/// Apply the selected Keccak-f[1600] implementation to a 25-lane state.
#[inline]
pub fn keccak_f1600(state: &mut [u64; 25]) {
    match selected_backend() {
        Backend::Scalar => ScalarBackend::keccak_f1600(state),
    }
}

/// Compute SHAKE128 using the selected backend.
#[inline]
pub fn shake128(input: &[u8], output: &mut [u8]) {
    match selected_backend() {
        Backend::Scalar => ScalarBackend::shake128(input, output),
    }
}

/// Compute SHAKE256 using the selected backend.
#[inline]
pub fn shake256(input: &[u8], output: &mut [u8]) {
    match selected_backend() {
        Backend::Scalar => ScalarBackend::shake256(input, output),
    }
}

/// Apply the selected ML-KEM number-theoretic transform in place.
#[inline]
pub fn ntt(poly: &mut Polynomial) {
    match selected_backend() {
        Backend::Scalar => ScalarBackend::ntt(poly),
    }
}

/// Apply the selected inverse ML-KEM number-theoretic transform in place.
#[inline]
pub fn inverse_ntt(poly: &mut Polynomial) {
    match selected_backend() {
        Backend::Scalar => ScalarBackend::inverse_ntt(poly),
    }
}

/// Multiply two ML-KEM polynomials using the selected backend.
#[inline]
pub fn basemul(lhs: &Polynomial, rhs: &Polynomial) -> Polynomial {
    match selected_backend() {
        Backend::Scalar => ScalarBackend::basemul(lhs, rhs),
    }
}

/// Reduce an integer using the selected backend.
#[inline]
pub fn reduce(value: i32) -> i16 {
    match selected_backend() {
        Backend::Scalar => ScalarBackend::reduce(value),
    }
}

/// Freeze an integer using the selected backend.
#[inline]
pub fn freeze(value: i32) -> i16 {
    match selected_backend() {
        Backend::Scalar => ScalarBackend::freeze(value),
    }
}

#[cfg(test)]
mod tests {
    use super::{basemul, freeze, inverse_ntt, keccak_f1600, ntt, reduce, shake128, shake256};
    use crate::scalar::{keccak, mlkem};

    #[test]
    fn routed_keccak_and_shake_match_scalar_reference() {
        let mut expected_state = [0_u64; 25];
        let mut actual_state = expected_state;
        keccak::keccak_f1600(&mut expected_state);
        keccak_f1600(&mut actual_state);
        assert_eq!(actual_state, expected_state);

        let input = b"nexus-q routed API";
        let mut expected128 = [0_u8; 32];
        let mut actual128 = [0_u8; 32];
        keccak::shake128(input, &mut expected128);
        shake128(input, &mut actual128);
        assert_eq!(actual128, expected128);

        let mut expected256 = [0_u8; 64];
        let mut actual256 = [0_u8; 64];
        keccak::shake256(input, &mut expected256);
        shake256(input, &mut actual256);
        assert_eq!(actual256, expected256);
    }

    #[test]
    fn routed_mlkem_operations_match_scalar_reference() {
        let mut expected: mlkem::Polynomial =
            std::array::from_fn(|i| ((i as i32 * 37) % mlkem::Q as i32) as i16);
        let mut actual = expected;
        mlkem::ntt(&mut expected);
        ntt(&mut actual);
        assert_eq!(actual, expected);

        mlkem::inverse_ntt(&mut expected);
        inverse_ntt(&mut actual);
        assert_eq!(actual, expected);

        let lhs = [3_i16; mlkem::N];
        let rhs = [7_i16; mlkem::N];
        assert_eq!(basemul(&lhs, &rhs), mlkem::basemul(&lhs, &rhs));
        assert_eq!(reduce(-12345), mlkem::reduce(-12345));
        assert_eq!(freeze(mlkem::Q as i32 + 19), mlkem::freeze(mlkem::Q as i32 + 19));
    }
}

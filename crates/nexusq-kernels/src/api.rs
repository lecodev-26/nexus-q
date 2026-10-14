//! Backend-routed entry points for primitive cryptographic kernels.
//!
//! Callers should use this module when they want the crate's dispatch policy to
//! choose an implementation. The current policy routes every operation to the
//! scalar reference backend; optimized implementations remain gated by Issue #23.

use crate::backend::{KernelBackend, ScalarBackend};
use crate::dispatch::{Backend, selected_backend};
use crate::scalar::mlkem::Polynomial;

/// Apply the selected `Keccak-f\[1600\]` implementation to a 25-lane state.
#[inline]
pub fn keccak_f1600(state: &mut [u64; 25]) {
    match selected_backend() {
        Backend::Scalar => ScalarBackend::keccak_f1600(state),
    }
}

/// Apply Keccak-f\[1600\] to four independent states in parallel when an
/// accelerated four-way kernel is available, otherwise use the scalar oracle.
///
/// The AVX2 implementation is intentionally exposed as a batch primitive; it
/// is not yet selected for single-state SHAKE or the top-level PQC flows.
#[inline]
pub fn keccak_f1600x4(states: &mut [[u64; 25]; 4]) {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::x86_64::avx2::keccak_f1600x4(states) {
            return;
        }
    }

    for state in states {
        ScalarBackend::keccak_f1600(state);
    }
}

/// Compute four independent SHAKE128 streams in parallel when all input and
/// output lengths match. Unequal lengths safely fall back to the scalar oracle.
pub fn shake128x4(inputs: [&[u8]; 4], outputs: &mut [&mut [u8]; 4]) {
    shake_x4(inputs, outputs, 168);
}

/// Compute four independent SHAKE256 streams in parallel when all input and
/// output lengths match. Unequal lengths safely fall back to the scalar oracle.
pub fn shake256x4(inputs: [&[u8]; 4], outputs: &mut [&mut [u8]; 4]) {
    shake_x4(inputs, outputs, 136);
}

fn shake_x4(inputs: [&[u8]; 4], outputs: &mut [&mut [u8]; 4], rate: usize) {
    let input_len = inputs[0].len();
    let output_len = outputs[0].len();
    if inputs.iter().any(|input| input.len() != input_len)
        || outputs.iter().any(|output| output.len() != output_len)
    {
        for (input, output) in inputs.into_iter().zip(outputs.iter_mut()) {
            match rate {
                168 => ScalarBackend::shake128(input, output),
                136 => ScalarBackend::shake256(input, output),
                _ => unreachable!("SHAKE rate is selected by the public wrapper"),
            }
        }
        return;
    }

    let mut states = [[0_u64; 25]; 4];
    let mut offset = 0;
    while input_len - offset >= rate {
        for lane in 0..4 {
            xor_bytes_into_state(&mut states[lane], &inputs[lane][offset..offset + rate]);
        }
        keccak_f1600x4(&mut states);
        offset += rate;
    }

    let remainder_len = input_len - offset;
    for lane in 0..4 {
        xor_bytes_into_state(&mut states[lane], &inputs[lane][offset..]);
        states[lane][remainder_len / 8] ^= 0x1f_u64 << ((remainder_len % 8) * 8);
        states[lane][(rate - 1) / 8] ^= 0x80_u64 << (((rate - 1) % 8) * 8);
    }
    keccak_f1600x4(&mut states);

    let mut written = 0;
    while written < output_len {
        let take = (output_len - written).min(rate);
        for lane in 0..4 {
            for (index, byte) in outputs[lane][written..written + take]
                .iter_mut()
                .enumerate()
            {
                *byte = (states[lane][index / 8] >> ((index % 8) * 8)) as u8;
            }
        }
        written += take;
        if written < output_len {
            keccak_f1600x4(&mut states);
        }
    }
}

fn xor_bytes_into_state(state: &mut [u64; 25], bytes: &[u8]) {
    for (index, byte) in bytes.iter().copied().enumerate() {
        state[index / 8] ^= u64::from(byte) << ((index % 8) * 8);
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
    use super::{
        basemul, freeze, inverse_ntt, keccak_f1600, keccak_f1600x4, ntt, reduce, shake128,
        shake128x4, shake256, shake256x4,
    };
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
    fn routed_four_way_keccak_matches_four_scalar_permutations() {
        let mut states = std::array::from_fn(|state_index| {
            std::array::from_fn(|lane_index| {
                (state_index as u64 + 3)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left((lane_index * 11 + state_index) as u32)
            })
        });
        let mut expected = states;
        for state in &mut expected {
            keccak::keccak_f1600(state);
        }

        keccak_f1600x4(&mut states);
        assert_eq!(states, expected);
    }

    #[test]
    fn four_way_shake_matches_scalar_at_absorb_and_squeeze_boundaries() {
        for (rate, output_len, is_128) in
            [(168_usize, 337_usize, true), (136_usize, 273_usize, false)]
        {
            for input_len in [0, 1, rate - 1, rate, rate + 1, rate * 2, rate * 2 + 7] {
                let inputs: [Vec<u8>; 4] = std::array::from_fn(|lane| {
                    (0..input_len)
                        .map(|index| (index as u8).wrapping_mul(17).wrapping_add(lane as u8 * 43))
                        .collect()
                });
                let mut expected: [Vec<u8>; 4] = std::array::from_fn(|_| vec![0; output_len]);
                let mut actual: [Vec<u8>; 4] = std::array::from_fn(|_| vec![0; output_len]);
                for lane in 0..4 {
                    if is_128 {
                        keccak::shake128(&inputs[lane], &mut expected[lane]);
                    } else {
                        keccak::shake256(&inputs[lane], &mut expected[lane]);
                    }
                }
                let mut output_refs: [&mut [u8]; 4] =
                    std::array::from_fn(|lane| actual[lane].as_mut_slice());
                let input_refs = std::array::from_fn(|lane| inputs[lane].as_slice());
                if is_128 {
                    shake128x4(input_refs, &mut output_refs);
                } else {
                    shake256x4(input_refs, &mut output_refs);
                }
                assert_eq!(actual, expected, "rate={rate}, input_len={input_len}");
            }
        }
    }

    #[test]
    fn four_way_shake_unequal_lengths_use_scalar_fallback() {
        let inputs: [&[u8]; 4] = [b"a", b"longer input", b"", b"third"];
        let mut outputs = [
            vec![0_u8; 32],
            vec![0_u8; 31],
            vec![0_u8; 32],
            vec![0_u8; 32],
        ];
        let mut expected = outputs.clone();
        for lane in 0..4 {
            keccak::shake128(inputs[lane], &mut expected[lane]);
        }
        let mut output_refs: [&mut [u8]; 4] =
            std::array::from_fn(|lane| outputs[lane].as_mut_slice());
        shake128x4(inputs, &mut output_refs);
        assert_eq!(outputs, expected);
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
        assert_eq!(
            freeze(mlkem::Q as i32 + 19),
            mlkem::freeze(mlkem::Q as i32 + 19)
        );
    }
}

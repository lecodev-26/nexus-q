//! Backend-routed entry points for primitive cryptographic kernels.
//!
//! Callers should use this module when they want the crate's dispatch policy to
//! choose an implementation. Single-state operations currently use the scalar
//! reference backend. The explicit four-state Keccak/SHAKE batch API can use the
//! x86_64 AVX2 permutation when supported; it is not yet integrated into top-level
//! ML-KEM/ML-DSA flows and remains subject to Issue #23 acceptance gates.

use crate::backend::{KernelBackend, ScalarBackend};
use crate::dispatch::{Backend, SelectionReason, dispatch_info, selected_backend};
use crate::scalar::keccak::Shake as ScalarShake;
use crate::scalar::mlkem::Polynomial;

/// Incremental SHAKE sponge exposed through the kernel API.
///
/// Input is absorbed in caller-provided chunks and output is squeezed directly
/// into caller-owned buffers, avoiding a concatenated input/output allocation.
/// This wrapper currently uses the portable scalar implementation; it does not
/// imply that single-state SIMD dispatch is available.
pub struct Shake {
    inner: ScalarShake,
}

/// Four independent incremental SHAKE sponges processed in lockstep.
///
/// Every call must provide equal input/output lengths for all four lanes. This
/// keeps absorb and squeeze positions synchronized so a single four-state
/// permutation is equivalent to four independent scalar permutations. Callers
/// with unequal lengths should use [`Shake`] or the one-shot batch helpers.
pub struct ShakeX4 {
    states: [[u64; 25]; 4],
    rate: usize,
    absorb_position: usize,
    squeeze_position: usize,
    squeezing: bool,
}

impl ShakeX4 {
    /// Create four incremental SHAKE128 sponges (168-byte rate).
    pub const fn new128() -> Self {
        Self::new(168)
    }

    /// Create four incremental SHAKE256 sponges (136-byte rate).
    pub const fn new256() -> Self {
        Self::new(136)
    }

    const fn new(rate: usize) -> Self {
        Self {
            states: [[0; 25]; 4],
            rate,
            absorb_position: 0,
            squeeze_position: 0,
            squeezing: false,
        }
    }

    /// Absorb one chunk per lane. All four chunks must have equal length.
    /// Panics if called after finalization or if lane lengths differ.
    pub fn absorb(&mut self, inputs: [&[u8]; 4]) {
        assert!(!self.squeezing, "cannot absorb after SHAKE finalization");
        let len = inputs[0].len();
        assert!(
            inputs.iter().all(|input| input.len() == len),
            "SHAKEx4 input lengths must match"
        );

        let mut position = 0;
        while position < len {
            // Most callers absorb complete byte strings into an empty sponge.
            // XOR complete little-endian lanes at once instead of performing
            // eight shifts and four per-byte updates for every 64-bit word.
            if self.absorb_position % 8 == 0
                && len - position >= 8
                && self.absorb_position + 8 <= self.rate
            {
                let lane_index = self.absorb_position / 8;
                for (state, input) in self.states.iter_mut().zip(inputs.iter()) {
                    let word = u64::from_le_bytes(
                        input[position..position + 8]
                            .try_into()
                            .expect("an eight-byte SHAKE lane was selected"),
                    );
                    state[lane_index] ^= word;
                }
                self.absorb_position += 8;
                position += 8;
            } else {
                let shift = (self.absorb_position % 8) * 8;
                let lane_index = self.absorb_position / 8;
                for (state, input) in self.states.iter_mut().zip(inputs.iter()) {
                    state[lane_index] ^= u64::from(input[position]) << shift;
                }
                self.absorb_position += 1;
                position += 1;
            }

            if self.absorb_position == self.rate {
                keccak_f1600x4(&mut self.states);
                self.absorb_position = 0;
            }
        }
    }

    /// Apply SHAKE domain separation to all four states.
    /// Repeated calls are harmless.
    pub fn finalize(&mut self) {
        if self.squeezing {
            return;
        }
        for state in &mut self.states {
            state[self.absorb_position / 8] ^= 0x1f_u64 << ((self.absorb_position % 8) * 8);
            state[(self.rate - 1) / 8] ^= 0x80_u64 << (((self.rate - 1) % 8) * 8);
        }
        keccak_f1600x4(&mut self.states);
        self.squeeze_position = 0;
        self.squeezing = true;
    }

    /// Squeeze equal-length output chunks into all four caller-owned buffers.
    /// Panics before finalization or if output lengths differ.
    pub fn squeeze(&mut self, outputs: [&mut [u8]; 4]) {
        assert!(self.squeezing, "SHAKE must be finalized before squeezing");
        let len = outputs[0].len();
        assert!(
            outputs.iter().all(|output| output.len() == len),
            "SHAKEx4 output lengths must match"
        );

        let [output0, output1, output2, output3] = outputs;
        let mut position = 0;
        while position < len {
            if self.squeeze_position == self.rate {
                keccak_f1600x4(&mut self.states);
                self.squeeze_position = 0;
            }

            // Emit complete little-endian words in one operation. Sampling
            // callers usually request long, equal-sized streams, so this
            // avoids repeating lane/shift arithmetic for every output byte.
            if self.squeeze_position % 8 == 0
                && len - position >= 8
                && self.squeeze_position + 8 <= self.rate
            {
                let lane_index = self.squeeze_position / 8;
                output0[position..position + 8]
                    .copy_from_slice(&self.states[0][lane_index].to_le_bytes());
                output1[position..position + 8]
                    .copy_from_slice(&self.states[1][lane_index].to_le_bytes());
                output2[position..position + 8]
                    .copy_from_slice(&self.states[2][lane_index].to_le_bytes());
                output3[position..position + 8]
                    .copy_from_slice(&self.states[3][lane_index].to_le_bytes());
                self.squeeze_position += 8;
                position += 8;
            } else {
                let lane_index = self.squeeze_position / 8;
                let shift = (self.squeeze_position % 8) * 8;
                output0[position] = (self.states[0][lane_index] >> shift) as u8;
                output1[position] = (self.states[1][lane_index] >> shift) as u8;
                output2[position] = (self.states[2][lane_index] >> shift) as u8;
                output3[position] = (self.states[3][lane_index] >> shift) as u8;
                self.squeeze_position += 1;
                position += 1;
            }
        }
    }
}

impl Shake {
    /// Create an incremental SHAKE128 sponge.
    pub const fn new128() -> Self {
        Self {
            inner: ScalarShake::new128(),
        }
    }

    /// Create an incremental SHAKE256 sponge.
    pub const fn new256() -> Self {
        Self {
            inner: ScalarShake::new256(),
        }
    }

    /// Absorb another input chunk. Chunks may be split at arbitrary boundaries.
    /// Panics if called after [`finalize`](Self::finalize).
    #[inline]
    pub fn absorb(&mut self, input: &[u8]) {
        self.inner.absorb(input);
    }

    /// Apply SHAKE domain separation and transition to squeezing.
    #[inline]
    pub fn finalize(&mut self) {
        self.inner.finalize();
    }

    /// Squeeze the next output bytes into a caller-provided buffer.
    /// Panics if called before [`finalize`](Self::finalize).
    #[inline]
    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.inner.squeeze(output);
    }
}

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
    let force_scalar = dispatch_info().reason == SelectionReason::ForcedScalar;
    #[cfg(target_arch = "x86_64")]
    {
        if !force_scalar && crate::x86_64::avx2::keccak_f1600x4(states) {
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
        Shake, ShakeX4, basemul, freeze, inverse_ntt, keccak_f1600, keccak_f1600x4, ntt, reduce,
        shake128, shake128x4, shake256, shake256x4,
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
    fn shake_known_answer_vectors_match_fips_202_outputs() {
        // SHAKE128("") first 32 bytes, from the FIPS 202 known-answer vector.
        let expected128 = [
            0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05,
            0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac,
            0xfa, 0x66, 0xef, 0x26,
        ];
        let mut actual128 = [0_u8; 32];
        shake128(b"", &mut actual128);
        assert_eq!(actual128, expected128);

        // SHAKE256("") first 64 bytes, from the FIPS 202 known-answer vector.
        let expected256 = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f, 0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00, 0xcb, 0x05,
            0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6, 0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
            0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe,
        ];
        let mut actual256 = [0_u8; 64];
        shake256(b"", &mut actual256);
        assert_eq!(actual256, expected256);
    }

    #[test]
    fn four_way_shake_known_answer_vectors_match_fips_202_outputs() {
        let expected128 = [
            0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05,
            0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac,
            0xfa, 0x66, 0xef, 0x26,
        ];
        let expected256 = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f, 0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00, 0xcb, 0x05,
            0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6, 0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
            0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe,
        ];
        let inputs: [&[u8]; 4] = [b"", b"", b"", b""];
        let mut outputs128 = [[0_u8; 32]; 4];
        let [o0, o1, o2, o3] = &mut outputs128;
        let mut refs128: [&mut [u8]; 4] = [o0, o1, o2, o3];
        shake128x4(inputs, &mut refs128);
        assert!(outputs128.iter().all(|output| output == &expected128));

        let mut outputs256 = [[0_u8; 64]; 4];
        let [o0, o1, o2, o3] = &mut outputs256;
        let mut refs256: [&mut [u8]; 4] = [o0, o1, o2, o3];
        shake256x4(inputs, &mut refs256);
        assert!(outputs256.iter().all(|output| output == &expected256));
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
                let [actual0, actual1, actual2, actual3] = &mut actual;
                let mut output_refs: [&mut [u8]; 4] = [
                    actual0.as_mut_slice(),
                    actual1.as_mut_slice(),
                    actual2.as_mut_slice(),
                    actual3.as_mut_slice(),
                ];
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
        let [output0, output1, output2, output3] = &mut outputs;
        let mut output_refs: [&mut [u8]; 4] = [
            output0.as_mut_slice(),
            output1.as_mut_slice(),
            output2.as_mut_slice(),
            output3.as_mut_slice(),
        ];
        shake128x4(inputs, &mut output_refs);
        assert_eq!(outputs, expected);
    }

    #[test]
    fn incremental_four_way_shake_matches_scalar_across_chunk_boundaries() {
        for (new_sponge, one_shot, rate) in [
            (
                ShakeX4::new128 as fn() -> ShakeX4,
                shake128 as fn(&[u8], &mut [u8]),
                168usize,
            ),
            (
                ShakeX4::new256 as fn() -> ShakeX4,
                shake256 as fn(&[u8], &mut [u8]),
                136usize,
            ),
        ] {
            for input_len in [0, 1, rate - 1, rate, rate + 1, rate * 2 + 7] {
                let inputs: [Vec<u8>; 4] = std::array::from_fn(|lane| {
                    (0..input_len)
                        .map(|i| (i as u8).wrapping_mul(13).wrapping_add((lane * 31) as u8))
                        .collect()
                });
                let mut expected: [Vec<u8>; 4] = std::array::from_fn(|_| vec![0; rate * 2 + 11]);
                for lane in 0..4 {
                    one_shot(&inputs[lane], &mut expected[lane]);
                }
                let mut sponge = new_sponge();
                let first: [&[u8]; 4] = std::array::from_fn(|lane| &inputs[lane][..input_len / 2]);
                let second: [&[u8]; 4] = std::array::from_fn(|lane| &inputs[lane][input_len / 2..]);
                sponge.absorb(first);
                sponge.absorb(second);
                sponge.finalize();
                sponge.finalize();
                let mut actual: [Vec<u8>; 4] = std::array::from_fn(|_| vec![0; rate * 2 + 11]);
                let [a, b, c, d] = &mut actual;
                sponge.squeeze([&mut a[..7], &mut b[..7], &mut c[..7], &mut d[..7]]);
                let [a, b, c, d] = &mut actual;
                sponge.squeeze([&mut a[7..], &mut b[7..], &mut c[7..], &mut d[7..]]);
                assert_eq!(actual, expected, "rate={rate}, input_len={input_len}");
            }
        }
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

    #[test]
    fn incremental_shake_matches_one_shot_across_chunk_boundaries() {
        let input: Vec<u8> = (0..401).map(|i| (i * 29) as u8).collect();

        for (new_sponge, one_shot) in [
            (
                Shake::new128 as fn() -> Shake,
                shake128 as fn(&[u8], &mut [u8]),
            ),
            (
                Shake::new256 as fn() -> Shake,
                shake256 as fn(&[u8], &mut [u8]),
            ),
        ] {
            let mut expected = vec![0_u8; 401];
            one_shot(&input, &mut expected);

            let mut sponge = new_sponge();
            sponge.absorb(&[]);
            sponge.absorb(&input[..1]);
            sponge.absorb(&[]);
            sponge.absorb(&input[1..168]);
            sponge.absorb(&input[168..337]);
            sponge.absorb(&input[337..]);
            sponge.absorb(&[]);
            sponge.finalize();
            sponge.finalize();

            let mut actual = vec![0_u8; 401];
            sponge.squeeze(&mut actual[..7]);
            sponge.squeeze(&mut actual[7..173]);
            sponge.squeeze(&mut actual[173..]);
            assert_eq!(actual, expected);
        }
    }
}

//! Four-way AVX2 `Keccak-f[1600]` permutation.
//!
//! Each vector holds the same lane from four independent states. This is aimed
//! at parallel SHAKE workloads (for example, matrix expansion), not single-state
//! calls. The scalar implementation remains the reference and fallback.

use core::arch::x86_64::{
    __m256i, _mm256_andnot_si256, _mm256_or_si256, _mm256_set_epi64x, _mm256_set1_epi64x,
    _mm256_sllv_epi64, _mm256_srlv_epi64, _mm256_storeu_si256, _mm256_xor_si256,
};

use crate::scalar::keccak::{ROTATION_OFFSETS, ROUND_CONSTANTS};

/// Permute four independent Keccak states in parallel when AVX2 is available.
///
/// Returns `false` without modifying the states when the CPU lacks AVX2, so
/// callers can run the portable scalar implementation as a fallback.
pub fn keccak_f1600x4(states: &mut [[u64; 25]; 4]) -> bool {
    if !std::is_x86_feature_detected!("avx2") {
        return false;
    }

    // SAFETY: Runtime detection above guarantees AVX2 support on this CPU.
    unsafe { keccak_f1600x4_avx2(states) };
    true
}

// SAFETY: This function requires AVX2; its only caller checks the runtime feature first.
#[target_feature(enable = "avx2")]
unsafe fn keccak_f1600x4_avx2(states: &mut [[u64; 25]; 4]) {
    let mut lanes: [__m256i; 25] = core::array::from_fn(|i| {
        _mm256_set_epi64x(
            states[3][i] as i64,
            states[2][i] as i64,
            states[1][i] as i64,
            states[0][i] as i64,
        )
    });

    let mut column = [_mm256_set1_epi64x(0); 5];
    let mut delta = [_mm256_set1_epi64x(0); 5];
    let mut moved = [_mm256_set1_epi64x(0); 25];

    for round_constant in ROUND_CONSTANTS {
        // Theta: all bitwise operations act on four independent states.
        for x in 0..5 {
            column[x] = _mm256_xor_si256(
                _mm256_xor_si256(lanes[x], lanes[x + 5]),
                _mm256_xor_si256(
                    _mm256_xor_si256(lanes[x + 10], lanes[x + 15]),
                    lanes[x + 20],
                ),
            );
        }
        // Compute deltas only after all five columns are available; otherwise
        // an earlier delta would observe a column overwritten in this round.
        for x in 0..5 {
            // SAFETY: This call is within the AVX2-targeted permutation function.
            let rotated = unsafe { rotate_left_64(column[(x + 1) % 5], 1) };
            delta[x] = _mm256_xor_si256(column[(x + 4) % 5], rotated);
        }
        for y in 0..5 {
            for x in 0..5 {
                lanes[x + 5 * y] = _mm256_xor_si256(lanes[x + 5 * y], delta[x]);
            }
        }

        // Rho + Pi. Destination mapping follows the scalar oracle exactly.
        for y in 0..5 {
            for x in 0..5 {
                let source = x + 5 * y;
                let destination = y + 5 * ((2 * x + 3 * y) % 5);
                // SAFETY: This call is within the AVX2-targeted permutation function.
                moved[destination] =
                    unsafe { rotate_left_64(lanes[source], ROTATION_OFFSETS[source]) };
            }
        }

        // Chi: andnot(a,b) computes !a & b, matching the Keccak definition.
        for y in 0..5 {
            for x in 0..5 {
                let index = x + 5 * y;
                lanes[index] = _mm256_xor_si256(
                    moved[index],
                    _mm256_andnot_si256(moved[(x + 1) % 5 + 5 * y], moved[(x + 2) % 5 + 5 * y]),
                );
            }
        }

        // Iota affects lane zero in each of the four states.
        lanes[0] = _mm256_xor_si256(lanes[0], _mm256_set1_epi64x(round_constant as i64));
    }

    for lane in 0..25 {
        let mut values = [0_u64; 4];
        // SAFETY: values points to four writable u64 lanes (32 bytes), and
        // storeu permits unaligned output. AVX2 is enabled for this function.
        unsafe { _mm256_storeu_si256(values.as_mut_ptr().cast::<__m256i>(), lanes[lane]) };
        for (state, output) in states.iter_mut().enumerate() {
            output[lane] = values[state];
        }
    }
}

// SAFETY: The caller must execute with AVX2 enabled; all current callers are
// inside `keccak_f1600x4_avx2`, which carries that target feature.
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn rotate_left_64(value: __m256i, amount: u32) -> __m256i {
    let left = _mm256_sllv_epi64(value, _mm256_set1_epi64x(i64::from(amount)));
    let right = _mm256_srlv_epi64(value, _mm256_set1_epi64x(i64::from(64 - amount)));
    _mm256_or_si256(left, right)
}

#[cfg(test)]
mod tests {
    use super::keccak_f1600x4;
    use crate::scalar::keccak::keccak_f1600;

    #[test]
    fn four_way_permutation_matches_scalar_for_zero_and_distinct_states() {
        let mut states = [[0_u64; 25]; 4];
        for (state_index, state) in states.iter_mut().enumerate() {
            for (lane_index, lane) in state.iter_mut().enumerate() {
                *lane = (state_index as u64 + 1)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left((lane_index * 7 + state_index) as u32)
                    ^ (lane_index as u64).wrapping_mul(0x0101_0101_0101_0101);
            }
        }
        states[0] = [0; 25];
        let original = states;
        let mut expected = states;
        for state in &mut expected {
            keccak_f1600(state);
        }

        let accelerated = keccak_f1600x4(&mut states);
        if accelerated {
            assert_eq!(states, expected);
        } else {
            // The public wrapper's contract is fail-closed on non-AVX2 CPUs.
            assert_eq!(states, original);
        }
    }

    #[test]
    fn four_way_permutation_matches_scalar_at_all_zero_state() {
        let mut states = [[0_u64; 25]; 4];
        let mut expected = states;
        for state in &mut expected {
            keccak_f1600(state);
        }
        if keccak_f1600x4(&mut states) {
            assert_eq!(states, expected);
        }
    }
}

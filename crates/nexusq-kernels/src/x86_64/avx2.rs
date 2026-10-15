//! Four-way AVX2 `Keccak-f\[1600\]` permutation.
//!
//! Each vector holds the same lane from four independent states. This is aimed
//! at parallel SHAKE workloads (for example, matrix expansion), not single-state
//! calls. The scalar implementation remains the reference and fallback.

use core::arch::asm;
use core::arch::x86_64::{
    __m256i, _mm_loadu_si128, _mm256_add_epi32, _mm256_and_si256, _mm256_andnot_si256,
    _mm256_blend_epi32, _mm256_cmpgt_epi32, _mm256_cvtepu16_epi32, _mm256_loadu_si256,
    _mm256_mul_epu32, _mm256_or_si256, _mm256_set_epi64x, _mm256_set1_epi32, _mm256_set1_epi64x,
    _mm256_setzero_si256, _mm256_slli_epi64, _mm256_sllv_epi64, _mm256_srli_epi64,
    _mm256_srlv_epi64, _mm256_storeu_si256, _mm256_sub_epi32, _mm256_xor_si256,
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

/// Run the forward ML-KEM NTT over canonical coefficients using AVX2 butterflies.
///
/// The public wrapper performs runtime AVX2 detection. Coefficients and twiddle
/// factors are in `0..3329`; all SIMD arithmetic is 32-bit, so products remain
/// below 2^24 before Barrett-style reduction. Stages with fewer than eight
/// butterflies per group use the scalar constant-time arithmetic fallback.
pub fn mlkem_ntt(poly: &mut [u16; 256]) -> bool {
    if !std::is_x86_feature_detected!("avx2") {
        return false;
    }
    // SAFETY: runtime detection guarantees AVX2 support for this call.
    unsafe { mlkem_ntt_avx2(poly) };
    true
}

const MLKEM_Q: i32 = 3329;
const MLKEM_RECIPROCAL: i32 = 1_290_167; // floor(2^32 / 3329)

const fn mlkem_zetas() -> [i32; 128] {
    let mut table = [0_i32; 128];
    let mut index = 0;
    while index < table.len() {
        let mut source = index as u8;
        let mut reversed = 0_u8;
        let mut bit = 0;
        while bit < 7 {
            reversed = (reversed << 1) | (source & 1);
            source >>= 1;
            bit += 1;
        }
        let mut exponent = reversed as u32;
        let mut result = 1_u32;
        let mut factor = 17_u32;
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = (result * factor) % MLKEM_Q as u32;
            }
            factor = (factor * factor) % MLKEM_Q as u32;
            exponent >>= 1;
        }
        table[index] = result as i32;
        index += 1;
    }
    table
}

const MLKEM_ZETAS: [i32; 128] = mlkem_zetas();

// SAFETY: caller must guarantee AVX2 support. All vector values remain small
// nonnegative signed i32 values, and every memory operation is bounded by the
// fixed 256-coefficient polynomial.
#[target_feature(enable = "avx2")]
unsafe fn mlkem_ntt_avx2(poly: &mut [u16; 256]) {
    let mut zeta_index = 1;
    let mut length = 128;
    while length >= 2 {
        for start in (0..256).step_by(2 * length) {
            let zeta = MLKEM_ZETAS[zeta_index];
            zeta_index += 1;
            let mut index = start;
            while index + 8 <= start + length {
                // Load eight u16 coefficients and widen them to eight i32 lanes.
                // SAFETY: each slice covers exactly eight readable coefficients.
                let left16 = unsafe { _mm_loadu_si128(poly.as_ptr().add(index).cast()) };
                // SAFETY: the right-hand butterfly slice also has eight coefficients.
                let right16 = unsafe { _mm_loadu_si128(poly.as_ptr().add(index + length).cast()) };
                let left = _mm256_cvtepu16_epi32(left16);
                let right = _mm256_cvtepu16_epi32(right16);
                // SAFETY: this function is itself AVX2-targeted and the runtime
                // wrapper checks AVX2 before entering it.
                let product = unsafe {
                    reduce_mlkem_product(mullo_i32x8_asm(right, _mm256_set1_epi32(zeta)))
                };
                let sum = _mm256_add_epi32(left, product);
                let sum_mask = _mm256_cmpgt_epi32(sum, _mm256_set1_epi32(MLKEM_Q - 1));
                let sum =
                    _mm256_sub_epi32(sum, _mm256_and_si256(sum_mask, _mm256_set1_epi32(MLKEM_Q)));
                let difference = _mm256_sub_epi32(left, product);
                let negative = _mm256_cmpgt_epi32(_mm256_setzero_si256(), difference);
                let difference = _mm256_add_epi32(
                    difference,
                    _mm256_and_si256(negative, _mm256_set1_epi32(MLKEM_Q)),
                );
                let mut sums = [0_i32; 8];
                let mut differences = [0_i32; 8];
                // SAFETY: both temporary arrays provide 32 writable bytes.
                unsafe {
                    _mm256_storeu_si256(sums.as_mut_ptr().cast(), sum);
                    _mm256_storeu_si256(differences.as_mut_ptr().cast(), difference);
                }
                for lane in 0..8 {
                    poly[index + lane] = sums[lane] as u16;
                    poly[index + length + lane] = differences[lane] as u16;
                }
                index += 8;
            }
            while index < start + length {
                let left = i32::from(poly[index]);
                let right = i32::from(poly[index + length]);
                let product = (zeta * right) % MLKEM_Q;
                poly[index] = ((left + product) % MLKEM_Q) as u16;
                poly[index + length] = (left - product).rem_euclid(MLKEM_Q) as u16;
                index += 1;
            }
        }
        length /= 2;
    }
}

/// Multiply two ML-KEM NTT polynomials using AVX2 and hand-written `vpmulld`.
///
/// All inputs are canonical coefficients in `0..3329`; `gamma` contains the 128
/// FIPS 203 base-case twiddles. Returns `false` without modifying `out` when AVX2
/// is unavailable. Intermediate products and sums remain below 2^25, so the
/// reciprocal reduction is exact after at most one conditional subtraction.
pub fn mlkem_basemul(
    lhs: &[u16; 256],
    rhs: &[u16; 256],
    gamma: &[u16; 128],
    out: &mut [u16; 256],
) -> bool {
    if !std::is_x86_feature_detected!("avx2") {
        return false;
    }
    // SAFETY: runtime feature detection guarantees AVX2 support.
    unsafe { mlkem_basemul_avx2(lhs, rhs, gamma, out) };
    true
}

// SAFETY: the only caller checks AVX2 support before entering this target-feature function.
#[target_feature(enable = "avx2")]
unsafe fn mlkem_basemul_avx2(
    lhs: &[u16; 256],
    rhs: &[u16; 256],
    gamma: &[u16; 128],
    out: &mut [u16; 256],
) {
    let mut a0 = [0_i32; 8];
    let mut a1 = [0_i32; 8];
    let mut b0 = [0_i32; 8];
    let mut b1 = [0_i32; 8];
    let mut g = [0_i32; 8];
    let mut c0 = [0_i32; 8];
    let mut c1 = [0_i32; 8];

    for base in (0..128).step_by(8) {
        for lane in 0..8 {
            let pair = base + lane;
            a0[lane] = i32::from(lhs[pair * 2]);
            a1[lane] = i32::from(lhs[pair * 2 + 1]);
            b0[lane] = i32::from(rhs[pair * 2]);
            b1[lane] = i32::from(rhs[pair * 2 + 1]);
            g[lane] = i32::from(gamma[pair]);
        }

        // SAFETY: all temporary arrays are exactly eight i32 values and thus
        // provide 32 readable bytes for each unaligned vector load.
        let (a0v, a1v, b0v, b1v, gv) = unsafe {
            (
                _mm256_loadu_si256(a0.as_ptr().cast()),
                _mm256_loadu_si256(a1.as_ptr().cast()),
                _mm256_loadu_si256(b0.as_ptr().cast()),
                _mm256_loadu_si256(b1.as_ptr().cast()),
                _mm256_loadu_si256(g.as_ptr().cast()),
            )
        };
        // SAFETY: this function is AVX2-targeted; all lane products are positive
        // and below 2^25, matching reduce_mlkem_product's documented range.
        // SAFETY: AVX2 was checked above; products of canonical coefficients fit the reducer range.
        let b1g = unsafe { reduce_mlkem_product(mullo_i32x8_asm(b1v, gv)) };
        // SAFETY: AVX2 was checked above; each product is at most 3328 squared.
        let p00 = unsafe { mullo_i32x8_asm(a0v, b0v) };
        // SAFETY: AVX2 was checked above; both operands are canonical coefficients.
        let p11 = unsafe { mullo_i32x8_asm(a1v, b1g) };
        // SAFETY: AVX2 was checked above; both operands are canonical coefficients.
        let p01 = unsafe { mullo_i32x8_asm(a0v, b1v) };
        // SAFETY: AVX2 was checked above; both operands are canonical coefficients.
        let p10 = unsafe { mullo_i32x8_asm(a1v, b0v) };
        // SAFETY: AVX2 was checked above; sums are below 2^25 and supported by the reducer.
        let c0v = unsafe { reduce_mlkem_product(_mm256_add_epi32(p00, p11)) };
        // SAFETY: AVX2 was checked above; sums are below 2^25 and supported by the reducer.
        let c1v = unsafe { reduce_mlkem_product(_mm256_add_epi32(p01, p10)) };
        // SAFETY: c0 and c1 each provide 32 writable bytes for eight lanes.
        unsafe {
            _mm256_storeu_si256(c0.as_mut_ptr().cast(), c0v);
            _mm256_storeu_si256(c1.as_mut_ptr().cast(), c1v);
        }
        for lane in 0..8 {
            out[(base + lane) * 2] = c0[lane] as u16;
            out[(base + lane) * 2 + 1] = c1[lane] as u16;
        }
    }
}

/// Run the inverse ML-KEM NTT, including multiplication by 128^-1 modulo q.
///
/// Coefficients are canonical `u16` values in `0..3329`. The caller must retain
/// the scalar fallback unless this function returns `true`.
pub fn mlkem_inverse_ntt(poly: &mut [u16; 256]) -> bool {
    if !std::is_x86_feature_detected!("avx2") {
        return false;
    }
    // SAFETY: runtime detection guarantees AVX2 support for this call.
    unsafe { mlkem_inverse_ntt_avx2(poly) };
    true
}

// SAFETY: caller checks AVX2 support; all loads/stores are bounded by the
// fixed 256-coefficient polynomial and all lane values fit signed i32.
#[target_feature(enable = "avx2")]
unsafe fn mlkem_inverse_ntt_avx2(poly: &mut [u16; 256]) {
    let mut zeta_index = 127;
    let mut length = 2;
    while length <= 128 {
        for start in (0..256).step_by(2 * length) {
            let zeta = MLKEM_ZETAS[zeta_index];
            zeta_index -= 1;
            let mut index = start;
            while index + 8 <= start + length {
                // SAFETY: the two butterfly slices each contain eight u16 values.
                let left16 = unsafe { _mm_loadu_si128(poly.as_ptr().add(index).cast()) };
                let right16 = unsafe { _mm_loadu_si128(poly.as_ptr().add(index + length).cast()) };
                let left = _mm256_cvtepu16_epi32(left16);
                let right = _mm256_cvtepu16_epi32(right16);
                let sum = _mm256_add_epi32(left, right);
                let sum_mask = _mm256_cmpgt_epi32(sum, _mm256_set1_epi32(MLKEM_Q - 1));
                let sum =
                    _mm256_sub_epi32(sum, _mm256_and_si256(sum_mask, _mm256_set1_epi32(MLKEM_Q)));
                let difference = _mm256_sub_epi32(right, left);
                let negative = _mm256_cmpgt_epi32(_mm256_setzero_si256(), difference);
                let difference = _mm256_add_epi32(
                    difference,
                    _mm256_and_si256(negative, _mm256_set1_epi32(MLKEM_Q)),
                );
                // SAFETY: this function is AVX2-targeted and products are below 2^24.
                let product = unsafe {
                    reduce_mlkem_product(mullo_i32x8_asm(difference, _mm256_set1_epi32(zeta)))
                };
                let mut sums = [0_i32; 8];
                let mut products = [0_i32; 8];
                // SAFETY: both arrays have room for eight 32-bit lanes.
                unsafe {
                    _mm256_storeu_si256(sums.as_mut_ptr().cast(), sum);
                    _mm256_storeu_si256(products.as_mut_ptr().cast(), product);
                }
                for lane in 0..8 {
                    poly[index + lane] = sums[lane] as u16;
                    poly[index + length + lane] = products[lane] as u16;
                }
                index += 8;
            }
            while index < start + length {
                let left = i32::from(poly[index]);
                let right = i32::from(poly[index + length]);
                poly[index] = ((left + right) % MLKEM_Q) as u16;
                let difference = (right - left).rem_euclid(MLKEM_Q);
                poly[index + length] = ((zeta * difference) % MLKEM_Q) as u16;
                index += 1;
            }
        }
        length *= 2;
    }

    // 128^-1 mod 3329 = 3303. This final scalar is public and all products
    // remain within the exact range supported by the Barrett-style reducer.
    let mut index = 0;
    while index < 256 {
        // SAFETY: the remaining input always has at least eight coefficients.
        let values16 = unsafe { _mm_loadu_si128(poly.as_ptr().add(index).cast()) };
        let values = _mm256_cvtepu16_epi32(values16);
        // SAFETY: this function is AVX2-targeted.
        let scaled =
            unsafe { reduce_mlkem_product(mullo_i32x8_asm(values, _mm256_set1_epi32(3303))) };
        let mut output = [0_i32; 8];
        // SAFETY: output has room for eight 32-bit lanes.
        unsafe { _mm256_storeu_si256(output.as_mut_ptr().cast(), scaled) };
        for lane in 0..8 {
            poly[index + lane] = output[lane] as u16;
        }
        index += 8;
    }
}

/// Hand-written AVX2 packed 32-bit multiply used by the ML-KEM NTT hot path.
///
/// The caller must be inside an AVX2-targeted routine after runtime feature
/// detection. Inputs are eight signed 32-bit lanes; `vpmulld` deliberately
/// retains each low 32-bit product, which is exact for the documented ML-KEM
/// bounds (< 2^24 for twiddle products and < 2^16 for reduction correction).
// SAFETY: caller must be in an AVX2-enabled function after runtime feature detection.
#[target_feature(enable = "avx2")]
unsafe fn mullo_i32x8_asm(lhs: __m256i, rhs: __m256i) -> __m256i {
    let output: __m256i;
    // SAFETY: this helper is called only from AVX2-targeted functions whose
    // public entry points check runtime AVX2 support. The instruction has no
    // memory operands and writes only its declared YMM output.
    unsafe {
        asm!(
            "vpmulld {output}, {lhs}, {rhs}",
            output = lateout(ymm_reg) output,
            lhs = in(ymm_reg) lhs,
            rhs = in(ymm_reg) rhs,
            options(pure, nomem, nostack),
        );
    }
    output
}

// AVX2 has no general packed 32x32->64 high-multiply. Compute the high halves
// of even and odd lanes separately, then interleave the quotient estimates.
/// # Safety
/// The caller must execute on a CPU supporting AVX2.
#[target_feature(enable = "avx2")]
// SAFETY: called only from the AVX2-targeted NTT routine after runtime feature
// detection. It performs no memory access or pointer arithmetic.
unsafe fn reduce_mlkem_product(value: __m256i) -> __m256i {
    let reciprocal = _mm256_set1_epi32(MLKEM_RECIPROCAL);
    let even_products = _mm256_mul_epu32(value, reciprocal);
    let odd_products = _mm256_mul_epu32(_mm256_srli_epi64(value, 32), reciprocal);
    let even_quotients = _mm256_srli_epi64(even_products, 32);
    // The odd 32-bit products were shifted into each 64-bit lane's low half
    // before multiplication, so move their quotients back to the high halves
    // before interleaving. Without this shift, odd quotient lanes stay zero.
    let odd_quotients = _mm256_slli_epi64(_mm256_srli_epi64(odd_products, 32), 32);
    let quotient = _mm256_blend_epi32(even_quotients, odd_quotients, 0b1010_1010);
    // SAFETY: this reducer is AVX2-targeted and is called only from AVX2 kernels.
    let correction = unsafe { mullo_i32x8_asm(quotient, _mm256_set1_epi32(MLKEM_Q)) };
    let remainder = _mm256_sub_epi32(value, correction);
    let needs_subtract = _mm256_cmpgt_epi32(remainder, _mm256_set1_epi32(MLKEM_Q - 1));
    _mm256_sub_epi32(
        remainder,
        _mm256_and_si256(needs_subtract, _mm256_set1_epi32(MLKEM_Q)),
    )
}

// SAFETY: The caller must execute with AVX2 enabled; callers are inside an
// AVX2-targeted kernel after the public wrapper's runtime feature check.
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn rotate_left_64(value: __m256i, amount: u32) -> __m256i {
    let left = _mm256_sllv_epi64(value, _mm256_set1_epi64x(i64::from(amount)));
    let right = _mm256_srlv_epi64(value, _mm256_set1_epi64x(i64::from(64 - amount)));
    _mm256_or_si256(left, right)
}

#[cfg(test)]
mod tests {
    use super::{keccak_f1600x4, mlkem_basemul, mlkem_inverse_ntt, mlkem_ntt};
    use crate::scalar::{keccak::keccak_f1600, mlkem};

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

    #[test]
    fn mlkem_ntt_assembly_path_matches_scalar_reference() {
        let mut input = core::array::from_fn(|i| ((i * 127 + 19) % 3329) as u16);
        let mut expected = input;
        let mut scalar = core::array::from_fn(|i| expected[i] as i16);
        mlkem::ntt(&mut scalar);
        for (dst, src) in expected.iter_mut().zip(scalar) {
            *dst = src as u16;
        }
        if mlkem_ntt(&mut input) {
            assert_eq!(input, expected);
        }
    }

    #[test]
    fn mlkem_basemul_assembly_path_matches_scalar_reference() {
        let lhs = core::array::from_fn(|i| ((i * 127 + 19) % 3329) as u16);
        let rhs = core::array::from_fn(|i| ((i * 211 + 7) % 3329) as u16);
        let gamma = core::array::from_fn(|i| {
            let mut source = i as u8;
            let mut reversed = 0_u8;
            for _ in 0..7 {
                reversed = (reversed << 1) | (source & 1);
                source >>= 1;
            }
            let mut exponent = u32::from(reversed) * 2 + 1;
            let mut factor = 17_u32;
            let mut result = 1_u32;
            while exponent != 0 {
                if exponent & 1 != 0 {
                    result = result * factor % 3329;
                }
                factor = factor * factor % 3329;
                exponent >>= 1;
            }
            result as u16
        });
        let mut expected = [0_u16; 256];
        for pair in 0..128 {
            let i = pair * 2;
            let b1g = u32::from(rhs[i + 1]) * u32::from(gamma[pair]) % 3329;
            expected[i] = ((u32::from(lhs[i]) * u32::from(rhs[i]) + u32::from(lhs[i + 1]) * b1g)
                % 3329) as u16;
            expected[i + 1] = ((u32::from(lhs[i]) * u32::from(rhs[i + 1])
                + u32::from(lhs[i + 1]) * u32::from(rhs[i]))
                % 3329) as u16;
        }
        let mut actual = [0_u16; 256];
        if mlkem_basemul(&lhs, &rhs, &gamma, &mut actual) {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn mlkem_inverse_ntt_assembly_path_matches_scalar_reference() {
        let mut input = core::array::from_fn(|i| ((i * 211 + 7) % 3329) as u16);
        let mut expected = input;
        let mut scalar = core::array::from_fn(|i| expected[i] as i16);
        mlkem::inverse_ntt(&mut scalar);
        for (dst, src) in expected.iter_mut().zip(scalar) {
            *dst = src as u16;
        }
        if mlkem_inverse_ntt(&mut input) {
            assert_eq!(input, expected);
        }
    }
}

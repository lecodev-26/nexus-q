//! Portable scalar ML-KEM polynomial transforms (FIPS 203, q = 3329).
//!
//! This is a correctness-oriented reference, not a constant-time or optimized
//! production backend. Coefficients are returned in canonical range `0..Q`.

/// ML-KEM polynomial degree.
pub const N: usize = 256;
/// ML-KEM modulus.
pub const Q: i16 = 3329;
/// A polynomial with 256 coefficients.
pub type Polynomial = [i16; N];

const ZETA: i32 = 17;
const ZETAS: [i16; 128] = build_zetas();
const GAMMAS: [i16; 128] = build_gammas();

const fn build_zetas() -> [i16; 128] {
    let mut table = [0_i16; 128];
    let mut index = 0;
    while index < table.len() {
        let exponent = bit_reverse_7(index as u8) as u32;
        table[index] = mod_pow(ZETA as u32, exponent, Q as u32) as i16;
        index += 1;
    }
    table
}

const fn build_gammas() -> [i16; 128] {
    let mut table = [0_i16; 128];
    let mut index = 0;
    while index < table.len() {
        let exponent = 2 * bit_reverse_7(index as u8) as u32 + 1;
        table[index] = mod_pow(ZETA as u32, exponent, Q as u32) as i16;
        index += 1;
    }
    table
}

const fn bit_reverse_7(value: u8) -> u8 {
    let mut source = value;
    let mut reversed = 0_u8;
    let mut bit = 0;
    while bit < 7 {
        reversed = (reversed << 1) | (source & 1);
        source >>= 1;
        bit += 1;
    }
    reversed
}

const fn mod_pow(base: u32, exponent: u32, modulus: u32) -> u32 {
    let mut result = 1_u64;
    let mut factor = base as u64;
    let mut power = exponent;
    while power != 0 {
        if power & 1 != 0 {
            result = (result * factor) % modulus as u64;
        }
        factor = (factor * factor) % modulus as u64;
        power >>= 1;
    }
    result as u32
}

#[inline]
fn canonical(value: i32) -> i16 {
    value.rem_euclid(Q as i32) as i16
}

/// In-place forward ML-KEM NTT, with output in the standard bit-reversed order.
///
/// This transform maps the polynomial representation into the NTT domain used
/// by ML-KEM. The implementation intentionally uses straightforward modular
/// arithmetic instead of Montgomery or lazy reductions.
pub fn ntt(poly: &mut Polynomial) {
    let mut zeta_index = 1;
    let mut length = N / 2;
    while length >= 2 {
        for start in (0..N).step_by(2 * length) {
            let zeta = i32::from(ZETAS[zeta_index]);
            zeta_index += 1;
            for index in start..start + length {
                let left = i32::from(poly[index]);
                let right = i32::from(poly[index + length]);
                let product = (zeta * right).rem_euclid(i32::from(Q));
                poly[index] = canonical(left + product);
                poly[index + length] = canonical(left - product);
            }
        }
        length /= 2;
    }
}

/// In-place inverse ML-KEM NTT, including multiplication by 128⁻¹ modulo Q.
///
/// The result is the original coefficient-domain polynomial, normalized into
/// `0..Q`. As with [`ntt`], this is a scalar reference implementation.
pub fn inverse_ntt(poly: &mut Polynomial) {
    let mut zeta_index = 127;
    let mut length = 2;
    while length <= N / 2 {
        for start in (0..N).step_by(2 * length) {
            let zeta = i32::from(ZETAS[zeta_index]);
            zeta_index -= 1;
            for index in start..start + length {
                let left = i32::from(poly[index]);
                let right = i32::from(poly[index + length]);
                poly[index] = canonical(left + right);
                let difference = canonical(right - left);
                poly[index + length] = canonical(zeta * i32::from(difference));
            }
        }
        length *= 2;
    }

    // 128^-1 mod 3329 = 3303.
    for coefficient in poly {
        *coefficient = canonical(i32::from(*coefficient) * 3303);
    }
}

/// Multiply two ML-KEM polynomials in NTT representation (FIPS 203).
///
/// This safe scalar implementation is a correctness reference, not a
/// constant-time optimized production kernel.
pub fn basemul(lhs: &Polynomial, rhs: &Polynomial) -> Polynomial {
    let mut out = [0_i16; N];
    for (pair, &gamma_value) in GAMMAS.iter().enumerate() {
        let index = pair * 2;
        let a0 = i64::from(lhs[index]);
        let a1 = i64::from(lhs[index + 1]);
        let b0 = i64::from(rhs[index]);
        let b1 = i64::from(rhs[index + 1]);
        let gamma = i64::from(gamma_value);
        out[index] = (a0 * b0 + gamma * a1 * b1).rem_euclid(i64::from(Q)) as i16;
        out[index + 1] = (a0 * b1 + a1 * b0).rem_euclid(i64::from(Q)) as i16;
    }
    out
}

/// Pack unsigned coefficients into a little-endian bit stream.
///
/// Coefficients are serialized least-significant bit first, as required by
/// ML-KEM encoding. Every value must fit in the selected `d`-bit width.
pub fn pack_coefficients(values: &[u16], d: u32) -> Vec<u8> {
    assert!((1..=12).contains(&d), "ML-KEM packing width must be 1..=12");
    let limit = 1_u16 << d;
    assert!(
        values.iter().all(|&value| value < limit),
        "coefficient does not fit in d bits"
    );
    let bit_len = values.len() * d as usize;
    let mut out = vec![0_u8; bit_len.div_ceil(8)];
    let mut bit_offset = 0_usize;
    for &value in values {
        for bit in 0..d {
            if (value >> bit) & 1 != 0 {
                out[bit_offset / 8] |= 1 << (bit_offset % 8);
            }
            bit_offset += 1;
        }
    }
    out
}

/// Unpack `count` unsigned coefficients from a little-endian bit stream.
pub fn unpack_coefficients(bytes: &[u8], d: u32, count: usize) -> Vec<u16> {
    assert!((1..=12).contains(&d), "ML-KEM packing width must be 1..=12");
    let bit_len = count * d as usize;
    assert!(
        bytes.len() >= bit_len.div_ceil(8),
        "not enough bytes for requested coefficients"
    );
    let mut out = Vec::with_capacity(count);
    let mut bit_offset = 0_usize;
    for _ in 0..count {
        let mut value = 0_u16;
        for bit in 0..d {
            let set = (bytes[bit_offset / 8] >> (bit_offset % 8)) & 1;
            value |= u16::from(set) << bit;
            bit_offset += 1;
        }
        out.push(value);
    }
    out
}

/// Reduce an integer coefficient to the canonical interval `0..Q`.
///
/// This simple modulo-based implementation is the scalar correctness oracle;
/// it is not intended to be a constant-time production reduction primitive.
#[inline]
pub fn reduce(value: i32) -> i16 {
    canonical(value)
}

/// Normalize a coefficient to its canonical representative modulo `Q`.
#[inline]
pub fn freeze(value: i32) -> i16 {
    canonical(value)
}

/// Compress one canonical ML-KEM coefficient to `d` bits (FIPS 203).
///
/// Supports the standardized widths `d = 1..=12`. Input values are first
/// normalized modulo `Q`; the returned integer is in `0..2^d`.
pub fn compress_coefficient(value: i16, d: u32) -> u16 {
    assert!(
        (1..=12).contains(&d),
        "ML-KEM compression width must be 1..=12"
    );
    let modulus = 1_i64 << d;
    let coefficient = i64::from(canonical(i32::from(value)));
    (((coefficient * modulus + i64::from(Q) / 2) / i64::from(Q)) % modulus) as u16
}

/// Decompress one `d`-bit ML-KEM coefficient (FIPS 203).
pub fn decompress_coefficient(value: u16, d: u32) -> i16 {
    assert!(
        (1..=12).contains(&d),
        "ML-KEM compression width must be 1..=12"
    );
    let modulus = 1_u32 << d;
    let reduced = u32::from(value) % modulus;
    ((u32::from(Q as u16) * reduced + (modulus / 2)) >> d) as i16
}

/// Compress and encode a polynomial for a ciphertext field using `d` bits.
///
/// This helper intentionally supports `d = 1..=11`; the uncompressed
/// 12-bit public-key encoding is a different operation and must not be rounded.
pub fn encode_compressed_polynomial(poly: &Polynomial, d: u32) -> Vec<u8> {
    assert!(
        (1..=11).contains(&d),
        "compressed polynomial width must be 1..=11"
    );
    let encoded: Vec<u16> = poly
        .iter()
        .map(|&coefficient| compress_coefficient(coefficient, d))
        .collect();
    pack_coefficients(&encoded, d)
}

/// Decode and decompress a polynomial field encoded with `d` bits.
pub fn decode_compressed_polynomial(bytes: &[u8], d: u32) -> Polynomial {
    assert!(
        (1..=11).contains(&d),
        "compressed polynomial width must be 1..=11"
    );
    let encoded = unpack_coefficients(bytes, d, N);
    core::array::from_fn(|index| decompress_coefficient(encoded[index], d))
}

/// Encode canonical polynomial coefficients as 12-bit values without compression.
pub fn encode_polynomial_12(poly: &Polynomial) -> Vec<u8> {
    let encoded: Vec<u16> = poly
        .iter()
        .map(|&coefficient| {
            let value = i32::from(canonical(i32::from(coefficient)));
            value as u16
        })
        .collect();
    pack_coefficients(&encoded, 12)
}

/// Decode a polynomial from its uncompressed 12-bit coefficient encoding.
pub fn decode_polynomial_12(bytes: &[u8]) -> Polynomial {
    let encoded = unpack_coefficients(bytes, 12, N);
    core::array::from_fn(|index| (u32::from(encoded[index]) % Q as u32) as i16)
}

/// Sample 256 centered-binomial coefficients from the supplied PRF bytes.
///
/// `eta` must be 2 or 3 and `input` must contain exactly `64 * eta` bytes.
/// Bits are consumed least-significant-bit first, as specified by FIPS 203.
/// This straightforward implementation is a scalar correctness reference.
pub fn sample_cbd(input: &[u8], eta: u32) -> Polynomial {
    assert!(eta == 2 || eta == 3, "ML-KEM eta must be 2 or 3");
    assert_eq!(input.len(), 64 * eta as usize, "incorrect CBD input length");

    let mut out = [0_i16; N];
    let eta = eta as usize;
    for (index, coefficient) in out.iter_mut().enumerate() {
        let first_bit = 2 * eta * index;
        let mut a = 0_i16;
        let mut b = 0_i16;
        for bit in 0..eta {
            let a_offset = first_bit + bit;
            let b_offset = first_bit + eta + bit;
            a += i16::from((input[a_offset / 8] >> (a_offset % 8)) & 1);
            b += i16::from((input[b_offset / 8] >> (b_offset % 8)) & 1);
        }
        *coefficient = a - b;
    }
    out
}

/// Parse ML-KEM SampleNTT rejection candidates from complete 3-byte groups.
///
/// Each group encodes two 12-bit candidates, least-significant nibble first;
/// candidates greater than or equal to `Q` are rejected. XOF expansion and
/// collection until 256 accepted coefficients remain belong to the caller.
pub fn rejection_sample(input: &[u8]) -> Vec<i16> {
    assert_eq!(
        input.len() % 3,
        0,
        "input must contain complete 3-byte groups"
    );
    let mut out = Vec::with_capacity(input.len() / 3 * 2);
    for chunk in input.chunks_exact(3) {
        let first = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0f) << 8);
        let second = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);
        if first < Q as u16 {
            out.push(first as i16);
        }
        if second < Q as u16 {
            out.push(second as i16);
        }
    }
    out
}

/// Build one 256-coefficient SampleNTT polynomial from available XOF bytes.
///
/// Returns `None` if the supplied complete 3-byte groups do not contain 256
/// accepted candidates. The caller is responsible for squeezing more XOF
/// output and retrying; this helper never fabricates missing coefficients.
pub fn sample_ntt_from_bytes(input: &[u8]) -> Option<Polynomial> {
    let accepted = rejection_sample(input);
    if accepted.len() < N {
        return None;
    }
    Some(core::array::from_fn(|index| accepted[index]))
}

#[cfg(test)]
mod tests {
    use super::{
        N, Polynomial, Q, basemul, compress_coefficient, decode_compressed_polynomial,
        decode_polynomial_12, decompress_coefficient, encode_compressed_polynomial,
        encode_polynomial_12, freeze, inverse_ntt, ntt, pack_coefficients, reduce,
        rejection_sample, sample_cbd, sample_ntt_from_bytes, unpack_coefficients,
    };

    fn sample_polynomial() -> Polynomial {
        core::array::from_fn(|index| ((index * 97 + index * index * 13 + 5) % Q as usize) as i16)
    }

    fn naive_negacyclic_product(lhs: &Polynomial, rhs: &Polynomial) -> Polynomial {
        let mut out = [0_i64; N];
        for (i, &left) in lhs.iter().enumerate() {
            for (j, &right) in rhs.iter().enumerate() {
                let index = i + j;
                let product = i64::from(left) * i64::from(right);
                if index < N {
                    out[index] += product;
                } else {
                    out[index - N] -= product;
                }
            }
        }
        core::array::from_fn(|i| out[i].rem_euclid(i64::from(Q)) as i16)
    }

    #[test]
    fn uncompressed_twelve_bit_polynomial_encoding_roundtrips() {
        let poly = sample_polynomial();
        let bytes = encode_polynomial_12(&poly);
        assert_eq!(bytes.len(), 384);
        assert_eq!(decode_polynomial_12(&bytes), poly);
    }

    #[test]
    fn compressed_polynomial_encoding_has_expected_size_and_error_bound() {
        let poly = sample_polynomial();
        for d in [1, 4, 10, 11] {
            let bytes = encode_compressed_polynomial(&poly, d);
            assert_eq!(bytes.len(), (N * d as usize) / 8);
            let restored = decode_compressed_polynomial(&bytes, d);
            let max_error = (i32::from(Q) + (1_i32 << d) - 1) / (1_i32 << d) + 1;
            for (&before, &after) in poly.iter().zip(restored.iter()) {
                let delta = (i32::from(before) - i32::from(after)).abs();
                let circular_delta = delta.min(i32::from(Q) - delta);
                assert!(
                    circular_delta <= max_error,
                    "d={d}, before={before}, after={after}"
                );
            }
        }
    }

    #[test]
    fn cbd_eta_two_and_three_respect_ranges_and_bit_order() {
        for eta in [2, 3] {
            let input = vec![0xff; 64 * eta];
            let output = sample_cbd(&input, eta as u32);
            assert!(output.iter().all(|&value| value == 0));

            let mut input = vec![0_u8; 64 * eta];
            input[0] = 0b0000_0011;
            let output = sample_cbd(&input, eta as u32);
            assert_eq!(output[0], 2);
            assert_eq!(output[1], 0);
            assert!(
                output
                    .iter()
                    .all(|&value| (-((eta) as i16)..=(eta as i16)).contains(&value))
            );
        }
    }

    #[test]
    fn rejection_sampler_accepts_only_values_below_modulus() {
        // Candidates: 1, 2, 3328, 3329, 4095, 0.
        let candidates = [1_u16, 2, 3328, 3329, 4095, 0];
        let mut bytes = Vec::new();
        for pair in candidates.chunks_exact(2) {
            bytes.push(pair[0] as u8);
            bytes.push(((pair[0] >> 8) as u8) | ((pair[1] as u8) << 4));
            bytes.push((pair[1] >> 4) as u8);
        }
        assert_eq!(rejection_sample(&bytes), vec![1, 2, 3328, 0]);
    }

    #[test]
    fn sample_ntt_requires_256_accepted_coefficients() {
        assert_eq!(sample_ntt_from_bytes(&[]), None);

        // Encode 256 zeros as 128 complete groups of three bytes.
        let zero_candidates = vec![0_u8; 128 * 3];
        let sampled = sample_ntt_from_bytes(&zero_candidates).expect("256 valid zero candidates");
        assert_eq!(sampled, [0_i16; N]);
    }

    #[test]
    fn sample_ntt_skips_rejected_candidates_and_keeps_first_256_valid() {
        // Each group encodes 0xD01 (rejected) followed by 7 (accepted).
        let mut bytes = Vec::new();
        for _ in 0..256 {
            let first = 0x0d01_u16;
            let second = 7_u16;
            bytes.push(first as u8);
            bytes.push(((first >> 8) as u8) | ((second as u8) << 4));
            bytes.push((second >> 4) as u8);
        }
        let sampled = sample_ntt_from_bytes(&bytes).expect("256 accepted candidates");
        assert_eq!(sampled, [7_i16; N]);
    }

    #[test]
    fn basemul_matches_negacyclic_polynomial_multiplication() {
        let lhs = sample_polynomial();
        let rhs = core::array::from_fn(|i| ((i * 53 + i * i * 7 + 11) % Q as usize) as i16);
        let expected = naive_negacyclic_product(&lhs, &rhs);
        let mut lhs_ntt = lhs;
        let mut rhs_ntt = rhs;
        ntt(&mut lhs_ntt);
        ntt(&mut rhs_ntt);
        let mut product_ntt = basemul(&lhs_ntt, &rhs_ntt);
        inverse_ntt(&mut product_ntt);
        assert_eq!(product_ntt, expected);
    }

    #[test]
    fn pack_unpack_roundtrip_for_standard_widths() {
        for d in 1..=12 {
            let limit = 1_u16 << d;
            let values: Vec<u16> = (0..N)
                .map(|i| ((i * 97 + i * i * 13 + 5) as u16) % limit)
                .collect();
            let packed = pack_coefficients(&values, d);
            assert_eq!(packed.len(), (N * d as usize).div_ceil(8));
            assert_eq!(unpack_coefficients(&packed, d, values.len()), values);
        }
    }

    #[test]
    fn packing_matches_known_little_endian_bitstream_vectors() {
        assert_eq!(pack_coefficients(&[1, 2, 3, 4], 3), [0xd1, 0x08]);
        assert_eq!(unpack_coefficients(&[0xd1, 0x08], 3, 4), [1, 2, 3, 4]);

        let mut polynomial = [0_i16; N];
        polynomial[0] = 0x123;
        polynomial[1] = 0x456;
        let encoded = encode_polynomial_12(&polynomial);
        assert_eq!(&encoded[..3], &[0x23, 0x61, 0x45]);
        assert_eq!(decode_polynomial_12(&encoded), polynomial);
    }

    #[test]
    fn compression_matches_integer_rounding_definition_exhaustively() {
        for d in 1..=11 {
            let levels = 1_i64 << d;
            for coefficient in 0..Q {
                let expected = (((i64::from(coefficient) * levels + i64::from(Q) / 2)
                    / i64::from(Q))
                    % levels) as u16;
                assert_eq!(
                    compress_coefficient(coefficient, d),
                    expected,
                    "d={d}, x={coefficient}"
                );
            }

            for encoded in 0..(1_u16 << d) {
                let expected = ((i64::from(Q) * i64::from(encoded) + (levels / 2)) / levels) as i16;
                assert_eq!(
                    decompress_coefficient(encoded, d),
                    expected,
                    "d={d}, y={encoded}"
                );
                assert_eq!(
                    compress_coefficient(decompress_coefficient(encoded, d), d),
                    encoded,
                    "decompress/compress d={d}, y={encoded}"
                );
            }
        }
    }

    #[test]
    fn pack_unpack_handles_non_byte_aligned_lengths() {
        let values = [1_u16, 2, 3, 4, 5];
        let packed = pack_coefficients(&values, 3);
        assert_eq!(packed.len(), 2);
        assert_eq!(unpack_coefficients(&packed, 3, values.len()), values);
    }

    #[test]
    fn reduce_and_freeze_return_canonical_coefficients() {
        for value in [-10_000_i32, -3_330, -1, 0, 1, 3_328, 3_329, 10_000] {
            let expected = value.rem_euclid(i32::from(Q)) as i16;
            assert_eq!(reduce(value), expected);
            assert_eq!(freeze(value), expected);
            assert!((0..Q).contains(&reduce(value)));
        }
    }

    #[test]
    fn compression_and_decompression_stay_in_range() {
        for d in 1..=12 {
            let limit = 1_u16 << d;
            for value in 0..Q {
                let packed = compress_coefficient(value, d);
                assert!(packed < limit);
                let unpacked = decompress_coefficient(packed, d);
                assert!((0..Q).contains(&unpacked));
            }
            assert_eq!(compress_coefficient(-1, d), compress_coefficient(Q - 1, d));
            assert_eq!(compress_coefficient(Q, d), compress_coefficient(0, d));
            assert_eq!(
                decompress_coefficient(limit, d),
                decompress_coefficient(0, d)
            );
        }
    }

    #[test]
    fn compression_roundtrip_error_is_bounded_by_quantization_step() {
        for d in 1..=12 {
            for value in 0..Q {
                let restored = i32::from(decompress_coefficient(compress_coefficient(value, d), d));
                let direct = i32::from(value);
                let circular_error = (restored - direct)
                    .abs()
                    .min(i32::from(Q) - (restored - direct).abs());
                assert!(circular_error <= (i32::from(Q) + (1_i32 << d) - 1) / (1_i32 << d));
            }
        }
    }

    #[test]
    fn zetas_match_bit_reversed_powers_of_seventeen() {
        assert_eq!(&super::ZETAS[..6], &[1, 1729, 2580, 3289, 2642, 630]);
    }

    #[test]
    fn ntt_of_constant_one_matches_pair_layout() {
        let mut polynomial = [0_i16; N];
        polynomial[0] = 1;
        ntt(&mut polynomial);
        let expected = core::array::from_fn(|index| if index % 2 == 0 { 1_i16 } else { 0_i16 });
        assert_eq!(polynomial, expected);
    }

    #[test]
    fn inverse_ntt_roundtrips_edge_and_dense_polynomials() {
        let mut edge = [0_i16; N];
        edge[0] = 1;
        edge[N - 1] = Q - 1;
        let mut dense = sample_polynomial();

        for polynomial in [&mut edge, &mut dense] {
            let expected = *polynomial;
            ntt(polynomial);
            assert!(polynomial.iter().all(|value| (0..Q).contains(value)));
            inverse_ntt(polynomial);
            assert_eq!(*polynomial, expected);
        }
    }

    #[test]
    fn transforms_keep_coefficients_canonical() {
        let mut polynomial = sample_polynomial();
        ntt(&mut polynomial);
        assert!(polynomial.iter().all(|value| (0..Q).contains(value)));
        inverse_ntt(&mut polynomial);
        assert!(polynomial.iter().all(|value| (0..Q).contains(value)));
    }
}

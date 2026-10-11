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

#[cfg(test)]
mod tests {
    use super::{N, Polynomial, Q, inverse_ntt, ntt};

    fn sample_polynomial() -> Polynomial {
        core::array::from_fn(|index| ((index * 97 + index * index * 13 + 5) % Q as usize) as i16)
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
        assert_eq!(
            polynomial,
            core::array::from_fn(|index| if index % 2 == 0 { 1 } else { 0 })
        );
    }

    #[test]
    fn inverse_ntt_roundtrips_edge_and_dense_polynomials() {
        let mut edge = [0_i16; N];
        edge[0] = 1;
        edge[N - 1] = Q - 1;
        let mut dense = sample_polynomial();

        for polynomial in [&mut edge, &mut dense] {
            let expected = **polynomial;
            ntt(polynomial);
            assert!(polynomial.iter().all(|value| (0..Q).contains(value)));
            inverse_ntt(polynomial);
            assert_eq!(**polynomial, expected);
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

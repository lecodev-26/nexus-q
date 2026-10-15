//! Portable scalar ML-DSA NTT reference (FIPS 204, q = 8,380,417).

pub const N: usize = 256;
pub const Q: u32 = 8_380_417;
const ZETA: u64 = 1753;

const fn zetas() -> [u32; N] {
    let mut powers = [0_u32; N];
    powers[0] = 1;
    let mut i = 1;
    let mut previous = 1_u64;
    while i < N {
        previous = (previous * ZETA) % Q as u64;
        powers[i] = previous as u32;
        i += 1;
    }
    let mut output = [0_u32; N];
    i = 1;
    while i < N {
        output[i] = powers[(i as u8).reverse_bits() as usize];
        i += 1;
    }
    output
}

const ZETAS: [u32; N] = zetas();
const BARRETT_SHIFT: u32 = 46;
const BARRETT_MULTIPLIER: u128 = (1_u128 << BARRETT_SHIFT) / Q as u128;

#[inline]
fn mul_reduce(lhs: u32, rhs: u32) -> u32 {
    let product = u128::from(lhs) * u128::from(rhs);
    let quotient = (product * BARRETT_MULTIPLIER) >> BARRETT_SHIFT;
    let remainder = (product - quotient * u128::from(Q)) as u32;
    remainder - (Q & 0_u32.wrapping_sub(u32::from(remainder >= Q)))
}

#[inline]
fn add(lhs: u32, rhs: u32) -> u32 {
    let sum = lhs + rhs;
    sum - (Q & 0_u32.wrapping_sub(u32::from(sum >= Q)))
}

#[inline]
fn sub(lhs: u32, rhs: u32) -> u32 {
    lhs.wrapping_sub(rhs)
        .wrapping_add(Q & 0_u32.wrapping_sub(u32::from(lhs < rhs)))
}

pub fn ntt(poly: &mut [u32; N]) {
    let mut k = 1;
    let mut length = N / 2;
    while length >= 1 {
        for start in (0..N).step_by(2 * length) {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + length {
                let product = mul_reduce(zeta, poly[j + length]);
                let left = poly[j];
                poly[j] = add(left, product);
                poly[j + length] = sub(left, product);
            }
        }
        length /= 2;
    }
}

pub fn inverse_ntt(poly: &mut [u32; N]) {
    let mut k = N - 1;
    let mut length = 1;
    while length <= N / 2 {
        for start in (0..N).step_by(2 * length) {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + length {
                let left = poly[j];
                let right = poly[j + length];
                poly[j] = add(left, right);
                poly[j + length] = mul_reduce(zeta, sub(right, left));
            }
        }
        length *= 2;
    }
    for value in poly {
        *value = mul_reduce(*value, 8_347_681);
    }
}

#[cfg(test)]
mod tests {
    use super::{Q, inverse_ntt, ntt};

    #[test]
    fn ntt_round_trip_and_boundaries() {
        for pattern in 0..5_u32 {
            let mut polynomial = core::array::from_fn(|i| match pattern {
                0 => 0,
                1 => Q - 1,
                2 => (i as u32) % Q,
                3 => ((i as u32) * 65_537 + 123) % Q,
                _ => {
                    if i % 2 == 0 {
                        Q - 1
                    } else {
                        0
                    }
                }
            });
            let original = polynomial;
            ntt(&mut polynomial);
            assert!(polynomial.iter().all(|&x| x < Q));
            inverse_ntt(&mut polynomial);
            assert_eq!(polynomial, original);
        }
    }
}

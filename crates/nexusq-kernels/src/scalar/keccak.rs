//! Portable Keccak-f[1600] and SHAKE reference implementation.
//!
//! This implementation favors a small, auditable scalar reference over speed.
//! It is intended as a differential-test oracle for later SIMD backends.

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

// Indexed as x + 5*y, as specified by Keccak's 5x5 lane state.
const ROTATION_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Applies the 24-round Keccak-f[1600] permutation to a 25-lane state.
///
/// Lane and byte ordering are little-endian, matching the SHA-3/SHAKE
/// specifications.
pub fn keccak_f1600(state: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        // Theta
        let mut column = [0_u64; 5];
        for x in 0..5 {
            column[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut delta = [0_u64; 5];
        for x in 0..5 {
            delta[x] = column[(x + 4) % 5] ^ column[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= delta[x];
            }
        }

        // Rho and Pi
        let mut moved = [0_u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let source = x + 5 * y;
                let new_x = y;
                let new_y = (2 * x + 3 * y) % 5;
                moved[new_x + 5 * new_y] = state[source].rotate_left(ROTATION_OFFSETS[source]);
            }
        }

        // Chi
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    moved[x + 5 * y] ^ ((!moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y]);
            }
        }

        // Iota
        state[0] ^= round_constant;
    }
}

/// Computes SHAKE128 output into the caller-provided buffer.
pub fn shake128(input: &[u8], output: &mut [u8]) {
    shake(input, output, 168);
}

/// Computes SHAKE256 output into the caller-provided buffer.
pub fn shake256(input: &[u8], output: &mut [u8]) {
    shake(input, output, 136);
}

fn shake(input: &[u8], output: &mut [u8], rate: usize) {
    let mut state = [0_u64; 25];

    // Absorb every complete rate block. SHAKE uses the Keccak domain suffix
    // 0x1f and the final rate byte's high bit for multi-rate padding.
    let mut blocks = input.chunks_exact(rate);
    for block in &mut blocks {
        xor_bytes_into_state(&mut state, block);
        keccak_f1600(&mut state);
    }

    let remainder = blocks.remainder();
    xor_bytes_into_state(&mut state, remainder);
    state[remainder.len() / 8] ^= 0x1f_u64 << ((remainder.len() % 8) * 8);
    state[(rate - 1) / 8] ^= 0x80_u64 << (((rate - 1) % 8) * 8);
    keccak_f1600(&mut state);

    let mut written = 0;
    while written < output.len() {
        let take = (output.len() - written).min(rate);
        for (index, byte) in output[written..written + take].iter_mut().enumerate() {
            *byte = (state[index / 8] >> ((index % 8) * 8)) as u8;
        }
        written += take;
        if written < output.len() {
            keccak_f1600(&mut state);
        }
    }
}

fn xor_bytes_into_state(state: &mut [u64; 25], bytes: &[u8]) {
    for (index, byte) in bytes.iter().copied().enumerate() {
        state[index / 8] ^= u64::from(byte) << ((index % 8) * 8);
    }
}

#[cfg(test)]
mod tests {
    use super::{keccak_f1600, shake128, shake256};

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid hex test vector"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn shake128_empty_known_answer() {
        let mut output = [0_u8; 32];
        shake128(b"", &mut output);
        assert_eq!(
            output.as_slice(),
            decode_hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        );
    }

    #[test]
    fn shake128_abc_known_answer() {
        let mut output = [0_u8; 32];
        shake128(b"abc", &mut output);
        assert_eq!(
            output.as_slice(),
            decode_hex("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8")
        );
    }

    #[test]
    fn shake256_empty_known_answer() {
        let mut output = [0_u8; 64];
        shake256(b"", &mut output);
        assert_eq!(
            output.as_slice(),
            decode_hex(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            )
        );
    }

    #[test]
    fn shake128_multiblock_input_known_answer() {
        let input = [0xa3_u8; 200];
        let mut output = [0_u8; 32];
        shake128(&input, &mut output);
        assert_eq!(
            output.as_slice(),
            decode_hex("131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037")
        );
    }

    #[test]
    fn shake_squeezes_across_rate_boundary() {
        let mut short = [0_u8; 32];
        let mut long = [0_u8; 200];
        shake128(b"multi-block output", &mut short);
        shake128(b"multi-block output", &mut long);
        assert_eq!(long[..short.len()], short);
        assert!(long[168..].iter().any(|byte| *byte != 0));
    }

    #[test]
    fn permutation_is_deterministic() {
        let mut left = [0_u64; 25];
        let mut right = [0_u64; 25];
        keccak_f1600(&mut left);
        keccak_f1600(&mut right);
        assert_eq!(left, right);
        assert_ne!(left, [0_u64; 25]);
    }
}

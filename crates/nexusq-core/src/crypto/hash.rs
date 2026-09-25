//! Cryptographic hash functions.
//!
//! NEXUS-Q uses hashing for digests, audit-chain links and as a building
//! block inside HKDF. The set of algorithms is fixed by
//! `docs/CRYPTOGRAPHY.md` §4.2; this module exposes them behind plain
//! functions that take and return byte slices.

use sha2::{Digest as _, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

/// Size in bytes of a SHA-256 digest.
pub const SHA256_OUTPUT_LEN: usize = 32;

/// Size in bytes of a SHA-512 digest.
pub const SHA512_OUTPUT_LEN: usize = 64;

/// Size in bytes of a SHA3-256 digest.
pub const SHA3_256_OUTPUT_LEN: usize = 32;

/// Size in bytes of a SHA3-512 digest.
pub const SHA3_512_OUTPUT_LEN: usize = 64;

/// Computes the SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Computes the SHA-512 digest of `data`.
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; SHA512_OUTPUT_LEN] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
}

/// Computes the SHA3-256 digest of `data`.
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; SHA3_256_OUTPUT_LEN] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

/// Computes the SHA3-512 digest of `data`.
#[must_use]
pub fn sha3_512(data: &[u8]) -> [u8; SHA3_512_OUTPUT_LEN] {
    let mut h = Sha3_512::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from FIPS 180-4 (SHA-2) and FIPS 202 (SHA-3).

    #[test]
    fn sha256_of_empty_input_matches_nist_vector() {
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(sha256(b"").as_slice(), expected.as_slice());
    }

    #[test]
    fn sha256_of_abc_matches_nist_vector() {
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(sha256(b"abc").as_slice(), expected.as_slice());
    }

    #[test]
    fn sha512_of_empty_input_matches_nist_vector() {
        let expected = hex::decode(concat!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ))
        .unwrap();
        assert_eq!(sha512(b"").as_slice(), expected.as_slice());
    }

    #[test]
    fn sha3_256_of_empty_input_matches_nist_vector() {
        let expected =
            hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
                .unwrap();
        assert_eq!(sha3_256(b"").as_slice(), expected.as_slice());
    }

    #[test]
    fn sha3_256_of_abc_matches_nist_vector() {
        let expected =
            hex::decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
                .unwrap();
        assert_eq!(sha3_256(b"abc").as_slice(), expected.as_slice());
    }

    #[test]
    fn sha3_512_of_empty_input_matches_nist_vector() {
        let expected = hex::decode(concat!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6",
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        ))
        .unwrap();
        assert_eq!(sha3_512(b"").as_slice(), expected.as_slice());
    }
}

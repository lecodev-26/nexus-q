//! Cryptographic primitives.

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod random;
pub mod sign;

pub use aead::{AeadError, Algorithm, decrypt, encrypt, random_nonce};
pub use hash::{sha3_256, sha3_512, sha256, sha512};
pub use kdf::{KdfError, argon2id, hkdf_sha256};
pub use kem::KemError;
pub use random::{OsRandomSource, RandomError, RandomSource};
pub use sign::{KeyPair, SignError, Signature, SigningKey, VerifyingKey};

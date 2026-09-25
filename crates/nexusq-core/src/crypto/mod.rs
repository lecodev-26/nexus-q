//! Cryptographic primitives.

pub mod random;

pub use random::{OsRandomSource, RandomError, RandomSource};

//! AXIOM NEXUS-Q core library.
//!
//! Post-quantum cryptographic engine for protecting data, keys, and
//! identities. This crate is the library that every other component
//! (CLI, server, SDKs) builds on top of.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod hardware;
pub mod identity;
pub mod policy;
pub mod storage;
pub mod vault;

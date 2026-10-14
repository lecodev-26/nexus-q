//! Low-level cryptographic kernels for NEXUS-Q.
//!
//! The scalar implementation is the correctness oracle. Optimized backends must
//! be added behind explicit runtime dispatch and must pass bit-exact differential
//! tests before they can be selected. No optimized or unsafe kernel is enabled
//! in this initial scaffold.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod api;
pub mod backend;
pub mod dispatch;
pub mod scalar;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

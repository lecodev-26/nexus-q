//! Concrete hardware backends.
//!
//! The [`software`] backend runs everywhere using ordinary OS
//! facilities. Hardware backends (TPM, HSM, Secure Element, RISC-V,
//! enclave) are added here as their platforms become available.

pub mod software;

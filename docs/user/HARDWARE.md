# Hardware Guide

NEXUS-Q is hardware-agnostic, but the current local backend is the software backend.

## Software backend

On ordinary Linux/Android systems the software backend provides:

- OS-backed cryptographic randomness.
- Encrypted file storage.
- In-memory key handling with zeroization where supported.
- Honest hardware/boot state reporting.

The software backend does not pretend that a general-purpose device has secure boot or hardware attestation.

## Hardware abstraction

The core defines interfaces for:

- randomness/TRNG;
- secure storage;
- key providers;
- secure memory;
- secure boot;
- measured boot;
- attestation.

These interfaces allow future TPM, HSM, Secure Element, enclave, and RISC-V secure-environment backends without changing the core API.

## Secure boot and attestation

Hardware-backed secure boot and attestation are not claimed as implemented local v1.0 features. See [Secure Boot](../SECURE_BOOT.md).

## RISC-V

The RISC-V target has a verified cross-compilation path. Building for RISC-V is not the same as executing the complete system on RISC-V hardware; runtime verification remains a dedicated platform/release gate.

See [Cross Compilation](../CROSS_COMPILE.md).

# NEXUS-Q

> Post-quantum cryptographic security engine for protecting data, keys, and identities.

**Status**: In active development. Phase 13 of 23 (SDK / API).

---

## What is NEXUS-Q?

NEXUS-Q is a post-quantum cryptographic security engine designed to
protect:

- **Data** — authenticated encryption of files and streams.
- **Keys** — full lifecycle management (generation, rotation,
  revocation, destruction).
- **Identities** — digital signatures and verifiable credentials.

It is meant to be used by:

- Applications (web, server, mobile).
- Servers.
- Devices with secure hardware (TPM, HSM, Secure Element, RISC-V,
  enclave).

---

## Design principles

1. **We do not invent cryptography.** Only standardized algorithms
   and audited libraries.
2. **Library-first.** The core is a Rust library; the CLI, SDKs and
   server are layers on top.
3. **Hardware-agnostic.** Abstraction from day one, so software, TPM,
   HSM and secure environments are interchangeable.
4. **Zeroization.** Secrets are wiped from memory when no longer
   needed.
5. **Auditability.** Every security-relevant operation is recorded in
   a tamper-evident log.
6. **Security from the ground up.** Threat model and cryptographic
   rules before code.

---

## Repository layout

The project is a Cargo workspace with five Rust crates, plus language bindings:

- `crates/nexusq-core` — the library. All cryptography, vault, key
  management, identity, policy, storage and hardware abstraction
  live here.
- `crates/nexusq-cli` — the `nexusq` binary. A thin wrapper over the
  library; no cryptography.
- `crates/nexusq-server` — the `nexusq-server` binary. Server foundation;
  network API work is scheduled for Phase 14.

---

## Status

Completed:

- Foundation documents, threat model, cryptographic rules.
- Crypto core: ML-KEM-768 hybrid with X25519, AES-256-GCM,
  ChaCha20-Poly1305, Ed25519, SHA-2, SHA-3, Argon2id, HKDF.
- Key management with full lifecycle.
- Encrypted vault (format F-01) with atomic writes.
- Envelope encryption (format F-02).
- Identities with signing, verification, rotation, revocation and
  signed credentials.
- Hardware abstraction traits for software, TPM, HSM, Secure Element
  and RISC-V.
- TRNG support with health checks and mixing.
- Cross-compilation to RISC-V verified.
- Storage: audit log with hash chaining, backup bundle, storage DB.
- Policy engine with deny-by-default.
- CLI covering vault, key, data, sign, identity, credential and audit
  commands.

In progress:

- SDK / API (Phase 13).

See `docs/ROADMAP.md` for the full plan.

---

## Requirements

- **Rust** 1.85 or newer (edition 2024).
- **Git** for repository operations.
- Additional SDK toolchains are only required when building a specific binding (C/C++, Python, Go, Ruby).
- Target platforms:
  - Linux (x86_64, aarch64).
  - Android / Termux (aarch64).
  - RISC-V (riscv64gc-unknown-linux-gnu) — build verified.
  - macOS and Windows: planned.

---

## Building

```bash
cargo build
cargo test
```

To build the CLI:

```bash
cargo build -p nexusq-cli
```

The binary is at target/debug/nexusq.

To build for RISC-V, see docs/CROSS_COMPILE.md.

---

Documentation

All technical documentation lives in docs/:

· ARCHITECTURE.md — system design.
· THREAT_MODEL.md — what we protect against.
· CRYPTOGRAPHY.md — algorithms and rules.
· KEY_MANAGEMENT.md — key lifecycle.
· SECURITY_MODEL.md — security guarantees.
· STORAGE.md — persistent formats.
· API.md — public interfaces.
· POLICY.md — access control engine.
· SECURE_BOOT.md — secure and measured boot.
· CROSS_COMPILE.md — cross-compilation guide.
· ROADMAP.md — the phased plan.
· adr/ — architecture decision records.

---

License

Dual-licensed under your choice of:

· MIT License — see LICENSE-MIT.
· Apache License 2.0 — see LICENSE-APACHE.

This follows the Rust ecosystem convention (the same choice as Rust,
Tokio and Serde).

---

Warning

This project is in early development. Do not use it in production yet.

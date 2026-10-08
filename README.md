# NEXUS-Q

[![Security and Release Gates](https://github.com/lecodev-26/nexus-q/actions/workflows/security-ci.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/security-ci.yml) [![SDK CI](https://github.com/lecodev-26/nexus-q/actions/workflows/sdk-ci.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/sdk-ci.yml) [![Benchmarks](https://github.com/lecodev-26/nexus-q/actions/workflows/benchmarks.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/benchmarks.yml) [![PQC Benchmark Arena](https://github.com/lecodev-26/nexus-q/actions/workflows/pqc-arena.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/pqc-arena.yml) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/license/mit)

> Post-quantum cryptographic security engine for protecting data, keys, and identities.

**Status**: **NEXUS-Q v2.0.0 engineering line frozen on `nexusqv2` and integrated into `main`.** V1 remains the frozen compatibility and benchmark baseline. V2 implementation, security/correctness gates, performance gate, release-candidate validation and final release gate are complete. PR #37 completed the V2-to-V1 compatibility integration into `main`; the post-merge `main` CI is the final validation checkpoint before the public GitHub v2.0.0 release. No external audit, certification, or downstream registry publication is implied.

---

## V2.0.0 closure status

V2.0.0 is frozen as a historical engineering release. It is integrated into main and retained on nexusqv2 for reproducibility and review.

The final benchmark record does not claim a performance improvement over V1. Corrected Arena runs produced geometric means of 0.885 and 1.0647513576 V2/V1, so performance remains an unresolved investigation item rather than a validated regression or improvement. The latest same-runner comparison measured V2 at +0.22% to +52.37% latency versus V1 across the nine NEXUS-Q operations; ML-DSA-65 signing is the dominant outlier at +52.37%.

### V1 vs V2 Arena comparison (latest corrected run)

| Operation | V1 | V2 | V2/V1 | Difference |
| --- | ---: | ---: | ---: | ---: |
| ML-KEM-768 keygen | 49.819 us | 51.185 us | 1.0274 | +2.74% |
| ML-KEM-768 encaps | 45.081 us | 46.063 us | 1.0218 | +2.18% |
| ML-KEM-768 decaps | 54.537 us | 55.997 us | 1.0268 | +2.68% |
| ML-KEM-1024 keygen | 81.264 us | 82.191 us | 1.0114 | +1.14% |
| ML-KEM-1024 encaps | 72.041 us | 73.221 us | 1.0164 | +1.64% |
| ML-KEM-1024 decaps | 83.992 us | 84.859 us | 1.0103 | +1.03% |
| ML-DSA-65 keygen | 283.730 us | 284.344 us | 1.0022 | +0.22% |
| ML-DSA-65 sign | 620.367 us | 945.226 us | 1.5237 | **+52.37%** |
| ML-DSA-65 verify | 181.798 us | 181.479 us | 0.9982 | -0.18% |

These are same-runner V1/V2 reference measurements from the retained Arena JSONL artifacts. The previous corrected run measured 0.885 V2/V1, demonstrating substantial run-to-run variance; V3 therefore begins with profiling and benchmark-variance investigation rather than assuming a single-run regression.

See docs/V2_PERFORMANCE_RESULTS.md for the complete numbers, methodology, and retained GitHub Actions artifacts.

Performance investigation is intentionally deferred to V3; V2 is not being modified to manufacture a benchmark result.

## What is NEXUS-Q?

NEXUS-Q is a post-quantum cryptographic security engine designed to
protect:

- **Data** — authenticated encryption of files and streams.
- **Keys** — full lifecycle management (generation, rotation,
  revocation, destruction).
- **Identities** — digital signatures and verifiable credentials.

It is intended as a cryptographic/security engine for applications and servers.
The repository also defines hardware-provider abstraction points for future TPM,
HSM, Secure Element, enclave and RISC-V integrations; the default software
backend does not itself provide hardware isolation.

---

## Design principles

1. **We do not invent cryptography.** Only standardized algorithms
   and maintained cryptographic libraries; dependency audit status is documented explicitly.
2. **Library-first.** The core is a Rust library; the CLI, SDKs and
   server are layers on top.
3. **Hardware-agnostic boundary.** Hardware-provider interfaces are separated
   from the software backend; concrete hardware isolation is only claimed when
   a provider is implemented and tested.
4. **Zeroization.** Secrets are wiped from memory when no longer
   needed.
5. **Auditability.** Auditable security state changes and cryptographic
   actions are recorded in a tamper-evident, HMAC-authenticated log.
6. **Security from the ground up.** Threat model and cryptographic
   rules before code.

---

## Repository layout

The project is a Cargo workspace with multiple Rust crates, plus language bindings:

- `crates/nexusq-core` — the library. All cryptography, vault, key
  management, identity, policy, storage and hardware abstraction
  live here.
- `crates/nexusq-cli` — the `nexusq` binary. A thin wrapper over the
  library; no cryptography.
- `crates/nexusq-server` — the `nexusq-server` binary and authenticated HTTP service.

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
- Storage: HMAC-authenticated audit log with rollback anchoring, backup bundle, storage DB.
- Policy engine with deny-by-default.
- CLI covering vault, key, data, sign, identity, credential and audit
  commands.


## v2.0.0 status

The v2 engineering line is frozen on `nexusqv2` at version `2.0.0`. V2 preserves the v1 security model while adding the completed performance, correctness/interoperability, security/fuzzing, backend-strategy and release gates. The final integration PR against `main` is the compatibility checkpoint between the frozen v1 baseline and v2.

The public GitHub v2.0.0 release is intentionally performed only after that integration path and its CI gates are green. Crates.io, PyPI and other SDK registries remain separate publication operations.

See [`docs/V2_ROADMAP.md`](docs/V2_ROADMAP.md), [`docs/V2_RELEASE.md`](docs/V2_RELEASE.md) and [`docs/V2_BENCHMARK_BASELINE.md`](docs/V2_BENCHMARK_BASELINE.md).

## v1.0 baseline status

The v1.0 engineering baseline is complete and intentionally frozen. The final CI/Arena evidence established a reproducible reference point for correctness, security gates, deployment, documentation and PQC performance.

The **PQC Benchmark Arena** compared NEXUS-Q against pinned external implementations on the same CI workload. The result is useful precisely because it is honest: NEXUS-Q is currently slower than the fastest mature implementations on the measured ML-KEM and ML-DSA operations. That is now the primary engineering target for **v2**.

The v1 baseline is therefore **not presented as a performance leader**, and no unsupported production-certification or independent-audit claim is made. External registry/package publication is intentionally deferred until v2 meets its performance and security gates.

See [`BENCHMARKS.md`](BENCHMARKS.md) for the measured baseline and [`docs/ROADMAP.md`](docs/ROADMAP.md) for the phase history.

For server installation and operations, see `docs/DEPLOYMENT.md` and `docs/SERVER.md`.

### Release deployment

```bash
cargo build --workspace --release
./deploy/package-release.sh
```

The generated archive contains the CLI, server, non-secret configuration
example, deployment documentation, and SHA-256 manifests. It does not contain
production tokens, vaults, private keys, or logs.

---

## Requirements

- **Rust** 1.85 or newer (edition 2024).
- **Git** for repository operations.
- Additional SDK toolchains are only required when building a specific binding (C/C++, Python, Go, Ruby).
- Target platforms:
  - Linux (x86_64, aarch64).
  - Android / Termux (aarch64).
  - RISC-V (riscv64gc-unknown-linux-gnu) — build verified.
  - macOS and Windows: release builds are validated by the V2 CI/release gate.

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

User-facing documentation starts at `docs/user/README.md`. Technical/reference documentation lives in `docs/:`

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

NEXUS-Q v1.0 is a frozen engineering baseline, not a public package release or independent security certification. The benchmark evidence is intentionally transparent: performance optimization is the principal v2 objective. Do not treat the v1 baseline as production-certified.

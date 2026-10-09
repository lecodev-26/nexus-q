# NEXUS-Q

[![Security and Release Gates](https://github.com/lecodev-26/nexus-q/actions/workflows/security-ci.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/security-ci.yml) [![SDK CI](https://github.com/lecodev-26/nexus-q/actions/workflows/sdk-ci.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/sdk-ci.yml) [![Benchmarks](https://github.com/lecodev-26/nexus-q/actions/workflows/benchmarks.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/benchmarks.yml) [![PQC Benchmark Arena](https://github.com/lecodev-26/nexus-q/actions/workflows/pqc-arena.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/pqc-arena.yml) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/license/mit)

> Post-quantum cryptographic security engine for protecting data, keys, and identities.

**Version status (2026-10-09):** V1 is the frozen baseline (`v1.0.0`); V2 is frozen on `nexusqv2` (`v2.0.0`); V3 has been integrated into `main` by [PR #45](https://github.com/lecodev-26/nexus-q/pull/45), with V3 Incremental CI and PQC Benchmark Arena evidence retained. The release includes a downloadable evidence archive and SHA-256 manifest. Post-release `main` CI and four-hour fuzz soaks are tracked separately; see the linked Actions runs for their current status. V4 is the planned architecture-specific performance-kernel line tracked by [Issue #23](https://github.com/lecodev-26/nexus-q/issues/23). No independent audit, certification, or downstream registry publication is implied.

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

## V3 engineering release and V4 status

V3 consolidates the hardened implementation, the reproducible PQC Benchmark Arena, dependency/profile diagnostics, corrected benchmark sampling and archived evidence. The paired V1/V3 investigation found median increases of +2.70% to +6.33% across the six measured ML-KEM operations in the recorded hosted-runner experiment; conventional ML-DSA verification was +6.40%, key generation +6.82%, and signing median -0.76%. These are observations from one CI runner and ten paired rounds, not universal performance claims. See [`BENCHMARKS.md`](BENCHMARKS.md) and the [forensic report](arena/results/issue-41-v1-v3-latency-root-cause.md).

The V3 GitHub release is an engineering release, not a claim of independent audit, certification, or registry publication. The four-hour fuzz soaks are tracked separately in `main` CI. V4 work can be prepared on its own branch, while the final V3 CI/fuzz result is reviewed.

V3 focuses on the hardened post-quantum implementation, reproducible Arena measurements, dependency/source diagnostics, and preservation of security controls. The latest recovered V1/V2/V3 artifacts and checksums are tracked in [`artifact-archive/README.md`](artifact-archive/README.md). The V1-to-V3 latency investigation is documented as a forensic report; it records observed differences and explicitly distinguishes hypotheses from proven causes. In particular, the ML-DSA-only zeroize control does not prove SHA3/SHAKE zeroization is the cause of the ML-KEM latency delta.

V4 is a **planned development line**, not a release. Its performance work is tracked by [Issue #23](https://github.com/lecodev-26/nexus-q/issues/23). The plan is to prototype AVX2/NEON kernels behind explicit feature dispatch, retain a portable fallback, and require differential tests, cryptographic test vectors, fuzzing, constant-time review, and repeatable same-hardware benchmarks before enabling optimized paths by default. Security zeroization must not be removed as a shortcut to improve latency.

See [`docs/V3_V4_ROADMAP.md`](docs/V3_V4_ROADMAP.md) for the version history and transition checklist. Issue #41 was closed by explicit project decision: V1 prioritizes speed, while V3 retains security hardening and accepts the observed performance cost. The forensic report documents measured deltas without claiming that zeroization explains every difference.

---

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

The GitHub V2.0.0 engineering release is historical. Crates.io, PyPI and other SDK registries remain separate publication operations.

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

Release and assurance note

V1, V2 and V3 are engineering version lines. A GitHub release does not imply independent security audit, certification, production readiness, or publication to crates.io/PyPI/other registries. V3 preserves zeroization and accepts the currently observed performance tradeoff. The V3 release carries the retained benchmark evidence archive. Review the latest `main` CI and four-hour fuzz-soak outcomes before declaring the final validation cycle complete.

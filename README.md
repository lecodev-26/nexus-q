<div align="center">

<img src="assets/logo.png" alt="NEXUS-Q logo" width="132">

<img src="assets/banner.jpg" alt="NEXUS-Q: post-quantum cryptographic security engine" width="100%">

[![Security and Release Gates](https://github.com/lecodev-26/nexus-q/actions/workflows/security-ci.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/security-ci.yml) [![SDK CI](https://github.com/lecodev-26/nexus-q/actions/workflows/sdk-ci.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/sdk-ci.yml) [![Benchmarks](https://github.com/lecodev-26/nexus-q/actions/workflows/benchmarks.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/benchmarks.yml) [![PQC Benchmark Arena](https://github.com/lecodev-26/nexus-q/actions/workflows/pqc-arena.yml/badge.svg?branch=main)](https://github.com/lecodev-26/nexus-q/actions/workflows/pqc-arena.yml) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/license/mit)

<a href="https://nexus-q.link"><picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/b-site.svg"><img src="assets/light/b-site.svg" alt="Project website" width="96"></picture></a>&nbsp;<a href="https://github.com/lecodev-26/nexus-q/releases/latest"><picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/b-rel.svg"><img src="assets/light/b-rel.svg" alt="Releases" width="104"></picture></a>&nbsp;<a href="docs/user/README.md"><picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/b-docs.svg"><img src="assets/light/b-docs.svg" alt="Documentation" width="151"></picture></a>&nbsp;<a href="SECURITY.md"><picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/b-sec.svg"><img src="assets/light/b-sec.svg" alt="Security policy" width="154"></picture></a>

**Post-quantum cryptographic security engine for protecting data, keys, and identities.**<br>A plain-language tour of the project lives on the website: [nexus-q.link](https://nexus-q.link).

</div>

> **Current project status (2026-10-19):** the workspace is versioned **4.1.0 — the stable line release** of the V4 work, ready for the final independent audit. V1 (`v1.0.0`), V2 (`v2.0.0`) and V3 (`v3-engineering-2026-10-09`) are retained engineering baselines; V4 native-backend work is integrated into `main` by [PR #54](https://github.com/lecodev-26/nexus-q/pull/54) at commit [`1c03968`](https://github.com/lecodev-26/nexus-q/commit/1c03968e9b8d5578020e571e2f25edc5a7165607) and was tagged [`v4-engineering-2026-10-16`](https://github.com/lecodev-26/nexus-q/tree/v4-engineering-2026-10-16) as an engineering snapshot before this release line. The official 1.5× median-and-p95 performance gate passed in the reviewed native-backend CI, and PR [#55](https://github.com/lecodev-26/nexus-q/pull/55) wires the backend into `nexusq-core` behind an explicitly opt-in `native-backend` feature. **The native backend remains experimental: the default `nexusq-core` build, the CLI and the SDKs still use RustCrypto for production call paths; the native path is opt-in only and is not enabled by default anywhere.** The production-path benchmark (native vs RustCrypto vs AWS-LC) passed the unchanged 1.5× median-and-p95 gate. Do not infer an independent audit, FIPS 140-3 validation, production readiness, or v1.0 release readiness. Evaluation commands and feature scope are documented in [`docs/performance/NATIVE_BACKEND_FEATURE.md`](docs/performance/NATIVE_BACKEND_FEATURE.md). See [`docs/performance/NATIVE_BACKEND.md`](docs/performance/NATIVE_BACKEND.md) and [`docs/V3_V4_ROADMAP.md`](docs/V3_V4_ROADMAP.md). Registry publication of the 4.1.0 line (crates.io, PyPI, Go, PHP, Ruby and the C SDK) is complete; see the Installation section.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/stats.svg"><img src="assets/light/stats.svg" alt="5 Rust crates, 5 SDK languages, 8 Arena implementations, 57 measurements" width="100%"></picture>

</div>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-overview.svg"><img src="assets/light/h-overview.svg" alt="Overview" width="100%"></picture>

</div>

NEXUS-Q is a post-quantum cryptographic security engine designed to protect:

| 🔒 Data | 🗝️ Keys | 🪪 Identities |
|---|---|---|
| Authenticated encryption of files and streams. | Full lifecycle management: generation, rotation, revocation, destruction. | Digital signatures and verifiable credentials. |

It is intended as a cryptographic/security engine for applications and servers. The repository also defines hardware-provider abstraction points for future TPM, HSM, Secure Element, enclave and RISC-V integrations; the default software backend does not itself provide hardware isolation.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-how.svg"><img src="assets/light/h-how.svg" alt="How it works" width="100%"></picture>

</div>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/flow.svg"><img src="assets/light/flow.svg" alt="Unlock the vault, manage keys, encrypt or sign, enforce policy, audit everything" width="100%"></picture>

</div>

Every operation goes through the same building blocks: a password unlocks an encrypted vault (format F-01, atomic writes), keys are managed through their full lifecycle, data is protected with envelope encryption (format F-02), a deny-by-default policy engine gates actions, and security-relevant events go to an HMAC-authenticated audit log with rollback anchoring.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-principles.svg"><img src="assets/light/h-principles.svg" alt="Design principles" width="100%"></picture>

</div>

1. **We do not invent cryptography.** Only standardized algorithms and maintained cryptographic libraries; dependency audit status is documented explicitly.
2. **Library-first.** The core is a Rust library; the CLI, SDKs and server are layers on top.
3. **Hardware-agnostic boundary.** Hardware-provider interfaces are separated from the software backend; concrete hardware isolation is only claimed when a provider is implemented and tested.
4. **Zeroization.** Secrets are wiped from memory when no longer needed.
5. **Auditability.** Auditable security state changes and cryptographic actions are recorded in a tamper-evident, HMAC-authenticated log.
6. **Security from the ground up.** Threat model and cryptographic rules before code.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-layout.svg"><img src="assets/light/h-layout.svg" alt="Repository layout" width="100%"></picture>

</div>

| Component | What it is |
|---|---|
| `crates/nexusq-core` | The library. All cryptography, vault, key management, identity, policy, storage and hardware abstraction live here. |
| `crates/nexusq-cli` | The `nexusq` binary. A thin wrapper over the library; no cryptography. |
| `crates/nexusq-server` | The `nexusq-server` binary and authenticated HTTP service. |
| `crates/nexusq-c` · `crates/nexusq-py` | The C SDK and the Python binding. |
| `bindings/` | Go, PHP and Ruby bindings. |
| `arena/` | The PQC Benchmark Arena: pinned external implementations and normalized JSONL output. |
| `fuzz/` · `artifact-archive/` | Fuzz targets and the archived V1/V2/V3 evidence with SHA-256 manifests. |
| `docs/` · `deploy/` · `examples/` | Documentation, release packaging and C examples. |

**Requirements:** Rust 1.85 or newer (edition 2024) and Git. Additional SDK toolchains are only required when building a specific binding (C/C++, Python, Go, Ruby).

**Target platforms:** Linux (x86_64, aarch64); Android / Termux (aarch64); RISC-V (`riscv64gc-unknown-linux-gnu`), build verified; macOS and Windows release builds are validated by the V2 CI/release gate.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-crypto.svg"><img src="assets/light/h-crypto.svg" alt="Cryptography" width="100%"></picture>

</div>

| Family | Purpose | Implemented |
|---|---|---|
| Randomness | Entropy for keys, nonces and salts | OS CSPRNG, TRNG support with health checks and mixing |
| Hashing | Digests and commitments | SHA-2, SHA-3 |
| KDF | Passwords and key material to keys | Argon2id, HKDF |
| AEAD | Symmetric authenticated encryption | AES-256-GCM, ChaCha20-Poly1305 |
| KEM | Post-quantum key encapsulation | ML-KEM-768 and ML-KEM-1024, hybrid with X25519 |
| Signatures | Authenticity | Ed25519, ML-DSA-65, SLH-DSA-SHAKE-128f |

The reference document is [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md). Planned algorithms must not be described as available until they are implemented and tested.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-status.svg"><img src="assets/light/h-status.svg" alt="Status" width="100%"></picture>

</div>

**Completed:**

- Foundation documents, threat model, cryptographic rules.
- Crypto core: ML-KEM-768 hybrid with X25519, AES-256-GCM, ChaCha20-Poly1305, Ed25519, SHA-2, SHA-3, Argon2id, HKDF.
- Key management with full lifecycle.
- Encrypted vault (format F-01) with atomic writes.
- Envelope encryption (format F-02).
- Identities with signing, verification, rotation, revocation and signed credentials.
- Hardware abstraction traits for software, TPM, HSM, Secure Element and RISC-V.
- TRNG support with health checks and mixing.
- Cross-compilation to RISC-V verified.
- Storage: HMAC-authenticated audit log with rollback anchoring, backup bundle, storage DB.
- Policy engine with deny-by-default.
- CLI covering vault, key, data, sign, identity, credential and audit commands.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-bench.svg"><img src="assets/light/h-bench.svg" alt="Benchmarks" width="100%"></picture>

</div>

NEXUS-Q is **not presented as a universal performance leader**. On the v4.1.0 stable line, the opt-in native backend measures 0.86×–1.05× of AWS-LC median latency across the nine ML-KEM and ML-DSA operations on the same CI runner, passing the official 1.5× median-and-p95 gate on every operation. The default `nexusq-core` build, the CLI and the SDKs still use RustCrypto for production call paths; the native path is opt-in and experimental. Lower latency is better.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/bars.svg"><img src="assets/light/bars.svg" alt="NEXUS-Q v4.1.0 (opt-in native backend) versus AWS-LC on nine ML-KEM and ML-DSA operations" width="100%"></picture>

</div>

<sub>v4.1.0 stable line, 2026-10-19: official 1.5× median-and-p95 production-path gate (opt-in native backend vs AWS-LC) from the green release CI on the merged v4.1.0 code — three alternating rounds per implementation, pooled medians and nearest-rank p95, 3,000 samples per operation per implementation on an AMD EPYC 7763 CI runner. The full PQC Benchmark Arena run of the same release (241 normalized measurements, eight comparators plus the V1/V1+zeroize/V3 controls) is retained as CI artifacts. Reported without a composite score.</sub>

| Operation | NEXUS-Q | AWS-LC | NEXUS-Q / AWS-LC |
|---|---:|---:|---:|
| ML-KEM-768 keygen | 12.90 µs | 12.33 µs | 1.05× |
| ML-KEM-768 encaps | 12.94 µs | 12.75 µs | 1.01× |
| ML-KEM-768 decaps | 15.38 µs | 15.43 µs | 1.00× |
| ML-KEM-1024 keygen | 18.34 µs | 17.85 µs | 1.03× |
| ML-KEM-1024 encaps | 18.66 µs | 18.56 µs | 1.01× |
| ML-KEM-1024 decaps | 22.01 µs | 22.19 µs | 0.99× |
| ML-DSA-65 keygen | 35.79 µs | 40.00 µs | 0.89× |
| ML-DSA-65 sign | 83.22 µs | 96.57 µs | 0.86× |
| ML-DSA-65 verify | 33.54 µs | 34.31 µs | 0.98× |

<details>
<summary><b>v1.0 Arena baseline (historical)</b></summary>

The v1 baseline was slower than the fastest mature implementations on the measured ML-KEM and ML-DSA operations; closing that gap was the primary engineering target of the V4 line.

<sub>Final v1.0 Arena run, 2026-10-05: 57 normalized measurements from eight implementations on the same x86_64 Linux CI environment, 20 iterations and 3 warmups. Reported without a composite score. Comparators: AWS-LC, Botan, CIRCL, liboqs, OpenSSL, PQ Code Package and RustCrypto KEMs. Raw measurements are retained as CI artifacts.</sub>

| Operation | NEXUS-Q v1 | Best measured comparator | NEXUS-Q v1 / best |
|---|---:|---:|---:|
| ML-KEM-768 keygen | 33.94 µs | AWS-LC, 11.44 µs | 2.97× |
| ML-KEM-768 encaps | 27.97 µs | AWS-LC, 12.11 µs | 2.31× |
| ML-KEM-768 decaps | 34.62 µs | AWS-LC, 15.07 µs | 2.30× |
| ML-KEM-1024 keygen | 53.89 µs | liboqs, 22.60 µs | 2.38× |
| ML-KEM-1024 encaps | 46.05 µs | liboqs, 22.71 µs | 2.03× |
| ML-KEM-1024 decaps | 52.14 µs | liboqs, 25.61 µs | 2.04× |
| ML-DSA-65 keygen | 168.69 µs | AWS-LC, 44.21 µs | 3.82× |
| ML-DSA-65 sign | 600.73 µs | AWS-LC, 134.75 µs | 4.46× |
| ML-DSA-65 verify | 101.20 µs | CIRCL, 22.92 µs | 4.42× |

</details>

<details>
<summary><b>V1 vs V2 (same-runner Arena comparison)</b></summary>

The final benchmark record does not claim a performance improvement over V1. Corrected Arena runs produced geometric means of 0.885 and 1.0647513576 V2/V1, so performance remains an unresolved investigation item rather than a validated regression or improvement. The latest same-runner comparison measured V2 at +0.22% to +52.37% latency versus V1 across the nine NEXUS-Q operations; ML-DSA-65 signing is the dominant outlier at +52.37%.

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

These are same-runner reference measurements from the retained Arena JSONL artifacts. The previous corrected run measured 0.885 V2/V1, demonstrating substantial run-to-run variance; V3 therefore begins with profiling and benchmark-variance investigation rather than assuming a single-run regression. See [`docs/V2_PERFORMANCE_RESULTS.md`](docs/V2_PERFORMANCE_RESULTS.md). Performance investigation is intentionally deferred to V3; V2 is not being modified to manufacture a benchmark result.

</details>

<details>
<summary><b>V1 vs V3 (paired investigation)</b></summary>

The paired V1/V3 investigation found median increases of +2.70% to +6.33% across the six measured ML-KEM operations in the recorded hosted-runner experiment; conventional ML-DSA verification was +6.40%, key generation +6.82%, and signing median -0.76%. These are observations from one CI runner and ten paired rounds, not universal performance claims. See [`BENCHMARKS.md`](BENCHMARKS.md) and the [forensic report](arena/results/issue-41-v1-v3-latency-root-cause.md).

The ML-DSA-only zeroize control does not prove SHA3/SHAKE zeroization is the cause of the ML-KEM latency delta. Issue #41 was closed by explicit project decision: V1 prioritizes speed, while V3 retains security hardening and accepts the observed performance cost.

</details>

<details>
<summary><b>V4.1.0 stable line (Arena run and production-path gate)</b></summary>

The v4.1.0 stable line release was validated on `main` with the full PQC Benchmark Arena and the official 1.5× median-and-p95 production-path gate; both are green on the release code (a post-merge compile fix for the pinned Rust 1.85.1 release toolchain landed as [PR #57](https://github.com/lecodev-26/nexus-q/pull/57)).

**Arena run (2026-10-19, commit [`70152eb`](https://github.com/lecodev-26/nexus-q/commit/70152ebcf92c7edfa97c99c5f767a43ecce1aa00)):** 241 normalized measurements on the same `ubuntu-24.04` x86_64 CI environment, 20 iterations and 3 warmups per operation. Comparators: AWS-LC (`ec05f25`), Botan 3.13.0, OpenSSL 3.5.9, CIRCL 1.6.4, RustCrypto KEMs, liboqs 0.16.0 and PQ Code Package, plus the retained V1 / V1+zeroize / V3 controls. Raw JSONL measurements are retained as [CI artifacts of the Arena run](https://github.com/lecodev-26/nexus-q/actions/runs/39186079459); reported without a composite score.

**Production-path gate (native backend vs AWS-LC, three alternating rounds per implementation, pooled medians and nearest-rank p95, 3,000 samples per operation per implementation):** all nine operations passed the unchanged 1.5× median-and-p95 gate on the merged release code ([gate run](https://github.com/lecodev-26/nexus-q/actions/runs/39182674176)).

| Operation | NEXUS-Q median | NEXUS-Q p95 | AWS-LC median | Median ratio | p95 ratio | Gate |
|---|---:|---:|---:|---:|---:|---|
| ML-KEM-768 keygen | 12.90 µs | 13.38 µs | 12.33 µs | 1.046 | 1.041 | pass |
| ML-KEM-768 encaps | 12.94 µs | 13.00 µs | 12.75 µs | 1.015 | 1.013 | pass |
| ML-KEM-768 decaps | 15.38 µs | 15.44 µs | 15.43 µs | 0.997 | 0.994 | pass |
| ML-KEM-1024 keygen | 18.34 µs | 18.86 µs | 17.85 µs | 1.028 | 1.025 | pass |
| ML-KEM-1024 encaps | 18.66 µs | 18.76 µs | 18.56 µs | 1.005 | 0.985 | pass |
| ML-KEM-1024 decaps | 22.01 µs | 22.10 µs | 22.19 µs | 0.992 | 0.977 | pass |
| ML-DSA-65 keygen | 35.79 µs | 36.62 µs | 40.00 µs | 0.895 | 0.885 | pass |
| ML-DSA-65 sign | 83.22 µs | 235.40 µs | 96.57 µs | 0.862 | 0.846 | pass |
| ML-DSA-65 verify | 33.54 µs | 34.01 µs | 34.31 µs | 0.978 | 0.976 | pass |

These are single-runner CI measurements on an AMD EPYC 7763 hosted runner, not universal performance claims. The native backend remains experimental and opt-in; the default `nexusq-core` build, the CLI and the SDKs still use RustCrypto for production call paths. See [`docs/performance/NATIVE_BACKEND_FEATURE.md`](docs/performance/NATIVE_BACKEND_FEATURE.md) and [`docs/V4_RELEASE.md`](docs/V4_RELEASE.md).

</details>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-versions.svg"><img src="assets/light/h-versions.svg" alt="Versions" width="100%"></picture>

</div>

| Line | Reference | Current meaning | Status |
|---|---|---|---|
| V1 | [`v1.0.0`](https://github.com/lecodev-26/nexus-q/releases/tag/v1.0.0) | Original frozen baseline | Historical engineering baseline |
| V2 | [`v2.0.0`](https://github.com/lecodev-26/nexus-q/releases/tag/v2.0.0) · `nexusqv2` | Security/correctness engineering line | Frozen |
| V3 | [`v3-engineering-2026-10-09`](https://github.com/lecodev-26/nexus-q/releases/tag/v3-engineering-2026-10-09) · `nexusqv3` | Hardened implementation and benchmark evidence | Engineering release |
| V4 | [`v4-engineering-2026-10-16`](https://github.com/lecodev-26/nexus-q/tree/v4-engineering-2026-10-16) · `nexusqv4` | Experimental native backend and performance work | Engineering snapshot (pre-release) |
| V4.1 | [`v4.1.0`](https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.0) · `main` | Stable line release: opt-in native-backend production-path wiring | **Current stable line — ready for the final independent audit (Phase 21)** |

<details>
<summary><b>V3 engineering release and V4 snapshot</b></summary>

V3 consolidates the hardened implementation, reproducible PQC Benchmark Arena, dependency/profile diagnostics, corrected benchmark sampling and archived evidence. Its GitHub release is an engineering release, not a claim of independent audit, certification, or registry publication. V1/V2/V3 artifacts and checksums are indexed in [`artifact-archive/README.md`](artifact-archive/README.md).

V4 is now represented by the `v4-engineering-2026-10-16` engineering tag and is integrated into `main`. The native backend and its benchmark harness are present, and the official 1.5× median-and-p95 gate passed in the reviewed CI evidence. PR [#55](https://github.com/lecodev-26/nexus-q/pull/55) wires the backend into `nexusq-core` behind an explicitly opt-in `native-backend` feature; the default build and all SDKs still use RustCrypto, the feature is not enabled by default anywhere, and the production-path benchmark passed the unchanged 1.5× median-and-p95 gate. It remains experimental and is not independently audited; the Phase 21 external audit is still open. The former Issue #48 tracking item is closed; its checklist is retained as historical engineering evidence under [`docs/performance/`](docs/performance/).

</details>

<details>
<summary><b>V2.0.0 and V1.0 status</b></summary>

The v2 engineering line is frozen on `nexusqv2` at version `2.0.0`. V2 preserves the v1 security model while adding the completed performance, correctness/interoperability, security/fuzzing, backend-strategy and release gates. The GitHub V2.0.0 engineering release is historical; crates.io, PyPI and other SDK registries remain separate publication operations. See [`docs/V2_ROADMAP.md`](docs/V2_ROADMAP.md), [`docs/V2_RELEASE.md`](docs/V2_RELEASE.md) and [`docs/V2_BENCHMARK_BASELINE.md`](docs/V2_BENCHMARK_BASELINE.md).

The v1.0 engineering baseline is complete and intentionally frozen. The final CI/Arena evidence established a reproducible reference point for correctness, security gates, deployment, documentation and PQC performance. The v1 baseline is **not presented as a performance leader**, and no unsupported production-certification or independent-audit claim is made. External registry/package publication is intentionally deferred. See [`BENCHMARKS.md`](BENCHMARKS.md) and [`docs/ROADMAP.md`](docs/ROADMAP.md).

</details>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-quick.svg"><img src="assets/light/h-quick.svg" alt="Quick start" width="100%"></picture>

</div>

```bash
# build the workspace
cargo build --workspace --release

# create and inspect a vault
./target/release/nexusq vault create ./example.nqv
./target/release/nexusq vault status ./example.nqv
./target/release/nexusq health

# generate a signing key (prefer --password-file over typing a password)
./target/release/nexusq key generate ./example.nqv --algorithm ed25519 --purpose sign --password-file ./password.txt

# encrypt and decrypt data
./target/release/nexusq data encrypt ./example.nqv --key-id <key-id> ./secret.txt
./target/release/nexusq data decrypt ./example.nqv ./secret.txt.nqx ./secret.out
```

Treat `password.txt` as a secret: restrict its permissions and never commit it. For development, `cargo build` and `cargo test` work as usual, and the CLI binary is at `target/debug/nexusq`. To build for RISC-V see [`docs/CROSS_COMPILE.md`](docs/CROSS_COMPILE.md).

**Release deployment:**

```bash
cargo build --workspace --release
./deploy/package-release.sh
```

The generated archive contains the CLI, server, non-secret configuration example, deployment documentation, and SHA-256 manifests. It does not contain production tokens, vaults, private keys, or logs. For server installation and operations see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and [`docs/SERVER.md`](docs/SERVER.md).

## Installation

The 4.1.0 stable line is published to the language package registries. The installation channel for each SDK:

| Channel | Install | Status |
|---|---|---|
| Rust library (all-in-one metacrate) | `cargo add nexusq` | Available — crates.io |
| Rust library (core only) | `cargo add nexusq-core` | Available — crates.io |
| Rust CLI | `cargo install nexusq-cli` | Available — crates.io |
| Rust server | `cargo install nexusq-server` | Available — crates.io |
| C / C++ SDK | `cargo cinstall -p nexusq-c` with [cargo-c], or build the C library from source with `cargo build -p nexusq-c` | Available — crates.io |
| Python | `pip install nexusq` | Available — PyPI |
| TypeScript / Node.js | `npm install nexusq` | Pending first npm publication — binding verified locally and wired into SDK CI (`bindings/typescript`) |
| Java | dependency `io.github.lecodev-26:nexusq` | Pending first Maven Central publication — binding verified locally and wired into SDK CI (`bindings/java`) |
| Kotlin | artifact `io.github.lecodev-26:nexusq-kotlin` | Pending first Maven Central publication — binding verified locally and wired into SDK CI (`bindings/kotlin`) |
| C# / .NET | `dotnet add package Nexusq` | Pending first NuGet publication — binding verified locally and wired into SDK CI (`bindings/dotnet`) |
| Swift | Swift Package Manager package at this repository (`bindings/swift`) | Pending first tagged release — binding verified locally and wired into SDK CI (`bindings/swift`) |
| Dart / Flutter | `dart pub add nexusq` | Pending first pub.dev publication — binding verified locally and wired into SDK CI (`bindings/dart`) |
| Go | `go get github.com/lecodev-26/nexus-q/bindings/go/nexusq` | Available — pkg.go.dev |
| PHP | `composer require lecodev-26/nexusq` | Available — Packagist |
| Ruby | `gem install nexusq` | Available — RubyGems.org |

Notes:

- The Go, PHP, Ruby, TypeScript, Java (JNA), Kotlin (JNA) and Dart bindings are thin FFI wrappers over the C SDK (`libnexusq`); build and install the C library first. The C#/.NET binding uses P/Invoke and the Swift binding links the C SDK through a Swift Package Manager system-library target, so both need the C library built and on the loader path as well.
- The Python package is a native extension module built from `crates/nexusq-py` (PyO3).
- The C SDK is consumable directly from C and C++.
- The GitHub release archive ships the CLI and server binaries, not the C SDK; build the C library from source or install it via cargo.
- Registry availability is a distribution channel, not a validation claim; see the security and assurance section below.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-docs.svg"><img src="assets/light/h-docs.svg" alt="Documentation" width="100%"></picture>

</div>

User-facing documentation starts at [`docs/user/README.md`](docs/user/README.md). Technical and reference documentation lives in `docs/`:

| Document | Covers |
|---|---|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | System design |
| [THREAT_MODEL](docs/THREAT_MODEL.md) | What we protect against |
| [CRYPTOGRAPHY](docs/CRYPTOGRAPHY.md) | Algorithms and rules |
| [KEY_MANAGEMENT](docs/KEY_MANAGEMENT.md) | Key lifecycle |
| [SECURITY_MODEL](docs/SECURITY_MODEL.md) | Security guarantees |
| [STORAGE](docs/STORAGE.md) | Persistent formats |
| [API](docs/API.md) | Public interfaces |
| [POLICY](docs/POLICY.md) | Access control engine |
| [SECURE_BOOT](docs/SECURE_BOOT.md) | Secure and measured boot |
| [CROSS_COMPILE](docs/CROSS_COMPILE.md) | Cross-compilation guide |
| [ROADMAP](docs/ROADMAP.md) | The phased plan |
| [adr/](docs/adr) | Architecture decision records |

<div align="center">

<a href="arena/README.md"><picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/b-arena.svg"><img src="assets/light/b-arena.svg" alt="Benchmark Arena" width="171"></picture></a>

</div>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-assurance.svg"><img src="assets/light/h-assurance.svg" alt="Security and assurance" width="100%"></picture>

</div>

V1–V4 are engineering version lines/snapshots, not proof of production readiness. A GitHub release does not imply an independent security audit, certification, FIPS validation, or production readiness; the same applies to registry publication, which is a distribution channel and not a validation claim. The V4 backend remains experimental and is not connected to the production cryptographic paths of `nexusq-core`, CLI, or SDKs. The performance gate result applies to the benchmarked backend and must not be read as an end-to-end application performance claim. Check [current `main` CI](https://github.com/lecodev-26/nexus-q/actions) before relying on any validation statement.

| ✅ Claimed and evidenced | ❌ Not claimed |
|---|---|
| Standardized algorithms through maintained libraries | Independent external audit |
| Secrets zeroized when no longer needed | FIPS validation or Common Criteria certification |
| Tamper-evident, HMAC-authenticated audit log | Formal verification |
| Deny-by-default policy engine | Production readiness |
| Security CI, SDK CI, benchmark CI and fuzz targets | Registry availability as an audit or production-readiness endorsement |
| Published threat model and security model | Hardware isolation from the default software backend |

Report suspected vulnerabilities privately through GitHub Security Advisories. See [`SECURITY.md`](SECURITY.md).

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="assets/dark/h-license.svg"><img src="assets/light/h-license.svg" alt="License" width="100%"></picture>

</div>

Dual-licensed under your choice of the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE). This follows the Rust ecosystem convention (the same choice as Rust, Tokio and Serde).

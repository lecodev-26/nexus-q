<div align="center">

<img src="https://raw.githubusercontent.com/lecodev-26/nexus-q/main/assets/logo.png" alt="NEXUS-Q logo" width="132">

[![Crates.io](https://img.shields.io/crates/v/nexusq.svg)](https://crates.io/crates/nexusq) [![Docs.rs](https://docs.rs/nexusq/badge.svg)](https://docs.rs/nexusq) [![License](https://img.shields.io/crates/l/nexusq.svg)](https://github.com/lecodev-26/nexus-q#license)

**Post-quantum cryptographic security engine for protecting data, keys, and identities.**

One dependency for the complete [NEXUS-Q](https://github.com/lecodev-26/nexus-q) Rust library stack.

</div>

## What it is

Every operation goes through the same building blocks: a password unlocks an
encrypted vault (format F-01, atomic writes), keys are managed through their
full lifecycle, data is protected with envelope encryption (format F-02), a
deny-by-default policy engine gates actions, and security-relevant events go
to an HMAC-authenticated audit log with rollback anchoring.

| Protects | Building blocks |
|---|---|
| **Data** — authenticated encryption of files and streams | Encrypted vault (F-01), envelope encryption (F-02) |
| **Keys** — generation, rotation, revocation, destruction | Full key lifecycle management |
| **Identities** — signatures and verifiable credentials | Ed25519 / ML-DSA signing, signed credentials |

## Installation

```bash
cargo add nexusq
```

This adds — and lets Cargo download and compile — the separately published
NEXUS-Q library crates:

| Crate | Role |
|---|---|
| `nexusq-core` | Core library: vault, identity, policy, crypto (depends on the crates below) |
| `nexusq-kernels` | Portable scalar reference kernels and audited dispatch boundary |
| `nexusq-ml-kem` | ML-KEM (FIPS 203) key encapsulation |
| `nexusq-ml-dsa` | ML-DSA (FIPS 204) signatures |

The crates remain independent on crates.io; this package only groups them so
`cargo add nexusq` works as a single command.

## Cryptographic surface

| Family | Algorithms |
|---|---|
| Randomness | OS CSPRNG, TRNG support with health checks and mixing |
| Hashing | SHA-2, SHA-3 |
| KDF | Argon2id, HKDF |
| AEAD | AES-256-GCM, ChaCha20-Poly1305 |
| KEM | ML-KEM-768 and ML-KEM-1024, hybrid with X25519 |
| Signatures | Ed25519, ML-DSA-65, SLH-DSA-SHAKE-128f |

Only standardized algorithms through maintained cryptographic libraries; the
reference document is [`docs/CRYPTOGRAPHY.md`](https://github.com/lecodev-26/nexus-q/blob/main/docs/CRYPTOGRAPHY.md).

## Performance — v4.1.0 stable line (opt-in native backend vs AWS-LC)

The official 1.5× median-and-p95 production-path gate passed on all nine
measured ML-KEM and ML-DSA operations on the same CI runner (three
alternating rounds per implementation, pooled medians and nearest-rank p95,
3,000 samples per operation per implementation, AMD EPYC 7763). Lower latency
is better.

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

These are single-runner CI measurements, not universal performance claims.
The native backend is **experimental and opt-in**: the default `nexusq-core`
build, the CLI and the SDKs still use RustCrypto for production call paths.
See the [performance documentation](https://github.com/lecodev-26/nexus-q/blob/main/docs/performance/NATIVE_BACKEND_FEATURE.md)
for the feature scope and evaluation commands.

## Usage

```rust
use nexusq::prelude::*;
```

The prelude mirrors `nexusq-core`'s. Each component is also reachable as a
module (`nexusq::nexusq_core`, `nexusq::nexusq_ml_kem`, ...).

## Notes

- The CLI and server are binary crates (`cargo install nexusq-cli`,
  `cargo install nexusq-server`) and are not part of this dependency.
- Prefer a minimal dependency tree? Add the individual crates instead
  (e.g. `cargo add nexusq-core`).
- V1–V4 are engineering version lines/snapshots, not proof of production
  readiness; registry availability is a distribution channel, not a
  validation claim. See the
  [security and assurance section](https://github.com/lecodev-26/nexus-q#security-and-assurance)
  of the repository README and [`SECURITY.md`](https://github.com/lecodev-26/nexus-q/blob/main/SECURITY.md).
- Full documentation: [repository docs](https://github.com/lecodev-26/nexus-q/tree/main/docs),
  [user guide](https://github.com/lecodev-26/nexus-q/tree/main/docs/user) and
  the project website [nexus-q.link](https://nexus-q.link).

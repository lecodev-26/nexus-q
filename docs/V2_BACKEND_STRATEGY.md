# NEXUS-Q v2 — Backend and Primitive Strategy

Status: strategy defined; no external cryptographic provider is enabled by default.

## 1. Decision

NEXUS-Q v2 keeps the current RustCrypto implementations as the canonical production software backend:
- ML-KEM 0.3.2, vendored and pinned in the workspace.
- module-lattice 0.2.3, vendored and pinned in the workspace.
- ML-DSA 0.1.1 using the workspace module-lattice dependency.
- Portable scalar arithmetic as the mandatory fallback.

V2-07 does not replace the canonical backend with an external/native provider merely because the v1 Arena showed faster implementations. Benchmark speed alone is not provider-selection evidence.

## 2. Evidence

The current backend has the strongest NEXUS-Q integration evidence: it is already used by the production crypto API and tests; V2-03/V2-04 retained measured compiler-level optimizations without changing FIPS 203/FIPS 204 semantics; V2-05 added an opt-in ML-DSA verification cache without changing the canonical Arena workload; and V2-06 found no dependency-provided SIMD backend that could be safely enabled.

The v1 Arena does justify investigating alternative providers, especially for ML-DSA performance. It does not by itself establish API/serialization equivalence, KAT coverage, invalid-input behavior, constant-time properties, zeroization, portability, reproducibility, maintenance, licensing, or supply-chain suitability.

## 3. Backend layers

### Canonical software backend

The default implementation linked into nexusq-core. It must remain portable, deterministic, compatible with existing NEXUS-Q serialization/error semantics, and free of architecture-specific runtime requirements.

### Optional optimized software backend

A future architecture-specific implementation may accelerate supported CPUs, but it requires a separate implementation boundary, runtime-safe feature selection or explicitly constrained build targets, a scalar fallback, KAT/interoperability parity, side-channel review, and reproducible Arena evidence. V2-06 did not identify an implementation meeting those requirements.

### External/native provider

A future native provider may be integrated behind an explicit boundary. FFI/unsafe code, provider-specific allocation/lifetime rules, error translation, serialization conversion, CPU capability handling, and zeroization guarantees must be isolated outside nexusq-core. The core crate keeps unsafe_code = forbid.

## 4. Primitive ownership

The public NEXUS-Q API owns the primitive contract, not a particular third-party implementation.

| Primitive | Canonical implementation | Default | Alternative |
|---|---|---|---|
| ML-KEM-768 | RustCrypto ml-kem 0.3.2 | Yes | Future candidate |
| ML-KEM-1024 | RustCrypto ml-kem 0.3.2 | Yes | Future candidate |
| ML-DSA-65 | RustCrypto ml-dsa 0.1.1 + module-lattice 0.2.3 | Yes | Future candidate |
| X25519 | Existing RustCrypto dependency | Yes | No switch justified |
| Ed25519 | Existing RustCrypto dependency | Yes | No switch justified |

## 5. Provider selection rule

Provider selection must be explicit and deterministic.

Rejected as the default strategy:
- silent provider selection based on CPU detection;
- provider changes based only on benchmark speed;
- build-wide target-cpu=native as the published portability model;
- changing NEXUS-Q serialized formats to fit a provider;
- making an external provider mandatory.

A future provider may be selected by an explicit Cargo feature, build target, or runtime dispatch mechanism only after its compatibility and security gates pass.

## 6. Required provider gate

An alternative provider is not production-eligible until all of these are demonstrated:
1. Correctness: all existing unit/integration/KAT tests pass.
2. Interoperability: byte-level compatibility with the canonical implementation and independent implementations where applicable.
3. Invalid inputs: required public error semantics remain compatible.
4. Security: constant-time review of secret-dependent operations and all FFI/unsafe boundaries.
5. Zeroization: secret material is cleared according to verified provider guarantees.
6. Portability: unsupported CPUs use the canonical scalar fallback.
7. Reproducibility: provider version/commit and native build inputs are pinned.
8. Performance: V2-10 Arena shows a reproducible benefit on the target workload.
9. Maintenance: upstream is actively maintained for the NEXUS-Q support window.
10. Licensing/supply chain: distribution and provenance are acceptable.
11. Release isolation: provider choice does not alter wire compatibility or public primitive identifiers.

Failure of any item keeps the provider experimental.

## 7. Decision matrix

| Option | V2 decision | Reason |
|---|---|---|
| RustCrypto portable backend | Adopt | Integrated, tested and portable |
| target-cpu=native | Reject | Not a portable/runtime-dispatched backend |
| Hand-written AVX2/AVX-512/NEON NTT | Defer | No evidence justifies the implementation risk yet |
| Replace backend solely for speed | Reject for now | Arena speed is insufficient provider evidence |
| Optional native provider boundary | Adopt as future architecture | Enables measured acceleration without changing canonical semantics |
| Multiple providers enabled by default | Reject | Increases attack surface and reproducibility complexity |
| Mandatory external provider | Reject | Removes portable fallback and raises deployment risk |

## 8. V2 consequence

V2-07 closes the architecture question without speculative crypto code:
- default: RustCrypto portable backend;
- fallback: the same portable scalar implementation;
- optimized/native providers: optional future work behind a narrow provider boundary;
- selection: explicit and deterministic;
- performance authority: V2-10 Arena;
- correctness/security authority: V2-08 and V2-09;
- release eligibility: V2-11/V2-12 after the provider gates pass.

The strategy intentionally does not create a generic provider abstraction before a second production-quality provider exists. An abstraction without a concrete second implementation would increase API surface and maintenance cost without a tested benefit.

## 9. Security invariants

V2-07 changes no FIPS 203/FIPS 204 parameters, cryptographic formulas, NEXUS-Q serialization formats, secret-dependent behavior in the canonical backend, zeroization behavior, or nexusq-core unsafe-code policy.

This phase is an architecture/decision gate, not a cryptographic implementation rewrite.


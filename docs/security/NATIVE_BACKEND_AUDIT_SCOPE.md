# Experimental native backend — separate security audit scope

**Decision:** Excluded from the NEXUS-Q v4.1.2 independent external audit.

**Decision owner:** `lecodev-26` (NEXUS-Q project maintainer).
**Recorded:** 2026-11-15.
**Status:** Binding project scope decision for the v4.1.2 audit candidate; a future audit requires a separate written scope and approval.

## Decision and rationale

The experimental native backend is not part of the v4.1.2 audit target. It remains an explicitly opt-in implementation and is not the default provider in the core, CLI, server, C/Python bindings, or published SDK build profiles. The default RustCrypto implementation and its ordinary production call paths remain in the v4.1.2 audit scope.

The native implementation adds a distinct security boundary: Rust-to-C FFI, architecture-specific C/assembly, runtime CPU dispatch, separately vendored cryptographic implementations, an independent Cargo lockfile, and backend-specific RNG/build configuration. Including it would require a separately frozen source snapshot, dependency inventory, platform matrix, and dedicated assurance plan. Treating existing engineering CI, differential tests, upstream proofs, constant-time harness results, or performance gates as a substitute for an independent review would overstate the evidence.

This exclusion is not a finding that the native backend is secure, audited, or production-ready. It is a scope boundary only. No production-readiness, FIPS 140-3, Common Criteria, or independent-audit claim is made for this backend.

## Boundary and interfaces to be reviewed in a future audit

The implementation boundary is `crates/nexusq-native-backend/`, plus its opt-in wiring in `crates/nexusq-core/` and the build/release workflows that can compile or distribute it.

- **Rust API:** safe byte-oriented wrappers for ML-KEM-768 and ML-KEM-1024 key generation, encapsulation, decapsulation, deterministic KAT helpers, and ML-DSA-65 key generation, signing, deterministic test signing, and verification. Public metadata reports the x86-64 AVX2/BMI2 dispatch state and which 1-way Keccak implementation is linked.
- **FFI boundary:** private Rust `unsafe extern "C"` declarations and the exported `nq_randombytes` callback; C ABI wrappers and compile-time prototype guards live in `csrc/nq_mlkem_all.c` and `csrc/nq_mldsa_all.c`.
- **Native implementation:** vendored C implementations, NEXUS-Q configuration headers, x86-64 and AArch64 assembly, and CPU-feature dispatch. `portable-only` selects the portable C implementation; the default feature-off core build uses RustCrypto instead.
- **Build and integration:** `build.rs`, the standalone `Cargo.toml`/`Cargo.lock`, the optional `nexusq-core` features `native-backend` and `native-backend-portable`, and the native runtime / backend gate workflows.

## Assets and security objectives

| Asset | Examples | Required protection in a future review |
|---|---|---|
| Long-term secret keys | ML-KEM decapsulation keys; ML-DSA signing keys; key-generation seeds | Confidentiality, correct zeroization, no unintended copies or disclosure |
| Ephemeral secrets | ML-KEM shared secrets; encapsulation randomness; ML-DSA hedging randomness | Confidentiality, uniqueness/unpredictability, correct failure handling and lifetime |
| Public cryptographic material | Encapsulation/verifying keys, ciphertexts, signatures | Correct encoding, validation, algorithm/parameter binding and interoperability |
| RNG boundary | OS CSPRNG output and C callback buffers | Cryptographic quality, correct buffer contract, fail-closed error propagation |
| Executable implementation | Rust, C, assembly, build scripts, vendored sources and compiled artifacts | Integrity, provenance, ABI correctness and safe architecture dispatch |
| Provider selection | Cargo features, runtime metadata, SDK artifacts | No silent fallback, substitution, or accidental enablement in default/release profiles |

## Dependency and provenance inventory

The backend is a separate Cargo workspace with its own lockfile. A future audit must freeze and verify that lockfile and every vendored source tree against the exact candidate commit.

- `mlkem-native` v2.0.0, upstream commit `d1b2fe78` (vendored under `vendor/mlkem-native`).
- `mldsa-native` v2.0.0, upstream commit `834a90d5` (vendored under `vendor/mldsa-native`).
- `s2n-bignum`, commit `4b5f8214e85b6b239077c278825b7fa9c2ab9cf5`, supplying the x86-64 scalar Keccak routine (vendored under `vendor/s2n-bignum`).
- Direct runtime/build dependencies in the standalone manifest: `getrandom`, `zeroize`, and `cc`; optional benchmark RNG feature `aws-lc-rs` (which links `aws-lc-sys`).
- Development dependencies: the NEXUS-Q RustCrypto ML-KEM and ML-DSA crates; local patch of `nexusq-kernels`.
- The exact resolved versions and checksums are in `crates/nexusq-native-backend/Cargo.lock`. The optional `aws-lc-rng` feature and its transitive AWS-LC dependencies must be included if enabled in the reviewed configuration.

The vendored s2n-bignum Keccak assembly is Apache-2.0-only and its `LICENSE`/`NOTICE` must accompany binaries that include it. The future audit must verify all vendored licenses and notices, not infer licensing from the root crate's license alone.

## Threats and residual risks retained by this exclusion

The following are explicitly not covered by the v4.1.2 external audit decision and remain open risks for any deployment that deliberately enables the feature:

1. **FFI memory safety and ABI drift:** invalid pointers, lengths, aliasing, integer-width mismatches, or prototype drift can cause undefined behavior or memory corruption. Compile-time guards reduce but do not eliminate this risk.
2. **Secret handling:** key/seed/shared-secret copies, stack temporaries, compiler transformations, crash dumps, swap, or incomplete zeroization may expose material. `ZeroizeOnDrop` is not a guarantee against a compromised host or every compiler/platform copy.
3. **Randomness:** OS CSPRNG failures, callback contract errors, or misuse of deterministic interfaces (especially reused/predictable ML-KEM encapsulation input) can compromise security. Errors must remain fail-closed.
4. **Side channels:** constant-time harnesses and upstream proofs provide evidence with limitations; they do not establish universal timing, cache, power, EM, or variable-latency instruction resistance on every supported CPU.
5. **Architecture dispatch:** incorrect CPU feature detection, assembly ABI assumptions, or unsupported-platform build behavior can cause faults or unsafe execution paths.
6. **Supply chain and build integrity:** vendored source drift, compromised dependencies/toolchains/build runners, lockfile changes, or artifact/provider substitution can undermine the implementation.
7. **Protocol and validation correctness:** malformed key/ciphertext/signature encodings, implicit-rejection behavior, parameter confusion, and divergence from FIPS 203/204 or the RustCrypto implementation require independent negative and interoperability review.
8. **Operational/provider selection:** downstream consumers may enable experimental features or distribute native artifacts despite the default-provider separation. Metadata and release checks do not replace consumer verification or an independent audit.

Existing differential tests, upstream KAT/ACVP suites, fuzzing, static checks, the Valgrind constant-time harness, and CI gates are useful engineering evidence. They are not an independent security audit and do not close the residual risks above.

## Conditions before production consideration

Do not enable this backend by default, advertise it as production-ready, or include it in a production SDK profile until all of the following are completed:

- A separate audit scope is agreed and approved, naming the exact source commit, target platforms, build configurations, feature flags, and artifacts.
- The reviewer receives the complete Rust/C/assembly source, both Cargo lockfiles, vendored source revisions, license notices, build scripts, CI evidence, and SBOM/provenance materials.
- The review explicitly covers FFI/memory safety, RNG, secret lifecycle/zeroization, side channels, CPU dispatch, parameter/encoding validation, provider selection, and supply-chain integrity.
- Dedicated negative testing, fuzzing, differential/KAT/ACVP validation, and platform-specific review are completed for the exact candidate snapshot.
- Findings are triaged and resolved or explicitly accepted by the maintainer, and the independent auditor's report and limitations are published or linked.

Reopen this decision whenever the native backend becomes default, is enabled in a published SDK/production profile, changes its cryptographic implementation or FFI boundary materially, or is proposed for a security claim covered by the v4.1.2 audit.

## Related documentation

- [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md) — v4.1.2 external audit scope and exclusions.
- [`../../SECURITY.md`](../../SECURITY.md) — public security policy.
- [`../performance/NATIVE_BACKEND.md`](../performance/NATIVE_BACKEND.md) — technical architecture and engineering evidence.
- [`../performance/NATIVE_BACKEND_FEATURE.md`](../performance/NATIVE_BACKEND_FEATURE.md) — opt-in feature and release restrictions.

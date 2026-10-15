# NEXUS-Q V4 / Issue #23 — Comparative ML-KEM and ML-DSA Kernel Audit

**Audit date:** 2026-10-15
**Reviewed revision:** `ffe84faf3ab2212778b140140578fa4cfc497e1b`
**Scope:** static source and benchmark-methodology audit only. No production implementation changed. No local build, test, or benchmark was run.

## Executive summary

The current performance gap is too large to attribute to the recent SHAKE x4 absorb/squeeze loops without component-level evidence. At the reviewed revision, the batch SHAKE path is only one part of ML-KEM matrix sampling, while the dominant polynomial arithmetic remains scalar; ML-DSA's production operations still use the vendored RustCrypto implementation and its scalar `module-lattice` arithmetic. The public NEXUS-Q kernel API has entry points for NTT, inverse NTT, and base multiplication, but those entry points currently dispatch only to `ScalarBackend`.

The existing CI profiler is useful for identifying allocation pressure and coarse end-to-end latency, but it is not a CPU sampling profiler and cannot identify which arithmetic function consumes cycles. Therefore the next optimization should be selected only after CI captures a call-stack profile (or equivalent sampled profile) for the nine gated workloads. Do not weaken the 1.5x gate or claim an improvement from source-level intuition.

## Evidence and findings

### F1 — No accelerated NTT/base multiplication is connected to the production operations

**Severity: High — performance / Issue #23 objective.**

- `crates/nexusq-kernels/src/api.rs`: the module-level documentation explicitly says single-state operations use the scalar reference backend and the four-state SHAKE API is not integrated into top-level ML-KEM/ML-DSA flows. `ntt`, `inverse_ntt`, and `basemul` each match `selected_backend()` and call `ScalarBackend`.
- `vendor/module-lattice/src/algebra.rs`: ML-KEM/ML-DSA polynomial and vector arithmetic is expressed through the shared generic lattice implementation (`MultiplyNtt`, `ntt`, `ntt_inverse`).
- `vendor/ml-kem/src/algebra.rs`: `matrix_sample_ntt` batches complete groups of four matrix polynomials into `sample_ntt_x4`; final one-to-three elements use the scalar reader. `sample_ntt_x4` uses `ShakeX4`, but the later key-generation, encryption, and decryption arithmetic still goes through `module-lattice`.
- `vendor/ml-dsa/src/signing.rs` and `vendor/ml-dsa/src/verifying.rs`: signing and verification repeatedly use `ntt`, matrix-vector multiplication, and inverse NTT; no NEXUS-Q SIMD kernel call is visible in these top-level paths.

**Implication:** SHAKE x4 is a limited path-specific optimization, not a vectorized ML-KEM/ML-DSA backend. NTT, inverse NTT, and polynomial multiply are plausible candidates, but static source alone does not establish which is the largest runtime cost.

### F2 — Current SHAKE x4 byte-loop changes do not establish an end-to-end gain

**Severity: High — evidence quality.**

- `crates/nexusq-kernels/src/api.rs`: `ShakeX4::absorb` and `ShakeX4::squeeze` use 64-bit word copies for aligned full words, retaining byte-wise fallbacks for partial or unaligned regions.
- The production ML-KEM matrix sampler requests 96-byte chunks and processes up to four lanes, but rejection sampling has per-lane completion counts. It still executes per-byte/per-coefficient parsing and scalar rejection logic.
- The latest recorded CI at `ffe84fa` passed Rust correctness/static gates but failed the 1.5x performance gate by several thousand times on most operations (reported ratios range roughly 2.4k–6.2k; ML-DSA verify median was the exception, while its p95 still failed). See the CI run and its artifact in the PR/issue discussion.

**Implication:** Do not describe the absorb/squeeze changes as a meaningful overall optimization until a same-host before/after comparison proves it. A small local loop improvement may be dwarfed by scalar arithmetic, allocation, hashing, or API overhead.

### F3 — The benchmark compares public operation boundaries, not isolated algorithm cores

**Severity: High — interpretation and prioritization.**

- `arena/adapters/aws-lc/README.md` documents that NEXUS-Q times direct RustCrypto `ml-kem` calls, while AWS-LC times its public EVP KEM API. AWS-LC includes EVP context creation for key generation and encapsulation/decapsulation; NEXUS-Q's ML-KEM-1024 ciphertext serialization copy is outside the timed interval.
- `.github/workflows/ci.yml` pins AWS-LC to `ec05f25ef5bcb1bf03d2e2f44ba57973a878e0ba`, builds it with CMake `Release`, and compiles the adapter with `cc -O3`. NEXUS-Q is built with Cargo `--release` and the runner's lockfile.
- `arena/runners/nexusq/Cargo.toml` pins the runner to the vendored `ml-kem 0.3.2`, `ml-dsa 0.1.1`, and `module-lattice 0.2.3` sources through `[patch.crates-io]`. It enables `ml-dsa`'s `nexusq-kernels` feature; Cargo feature unification means the kernel feature may be active in the shared dependency graph, but that does not imply the KEM/DSA arithmetic dispatches to SIMD.
- The benchmark's `fips_operation_v1` contract is explicit, and both runners do pre-measurement KEM round-trip checks. The remaining API-layer asymmetry is documented rather than hidden.

**Implication:** These measurements are valid signals of the current shipped API paths, but should not be interpreted as a pure primitive-core comparison. Preserve the current gate; additionally report core-level profiles and, when practical, a second matched-boundary comparison.

### F4 — Existing `profile_hotspots` output is allocation accounting plus coarse timing, not a sampled CPU profile

**Severity: High — next diagnostic step.**

- `arena/runners/nexusq/src/bin/profile_hotspots.rs` replaces the global allocator with a counter for alloc/dealloc/realloc counts and byte totals, then times 2,000 repeated operations with `Instant`.
- It has warmup loops and covers ML-KEM-768/1024 keygen, encapsulation and decapsulation, plus ML-DSA-65 keygen, sign, verify and cached verify.
- `.github/workflows/ci.yml` builds and runs it on the Linux CI runner and uploads its text output with the Phase 0 evidence artifact.
- It does **not** collect instruction-level samples, call stacks, cycle attribution by function, assembly annotations, or allocation call sites. Its one elapsed interval per workload cannot separate SHAKE, NTT, base multiplication, packing, rejection sampling, or zeroization costs.

**Implication:** Read the latest `profile-hotspots.txt` first for allocation pressure, but do not treat its `ns_per_op` as proof of a CPU hotspot. Add a separate diagnostic CI step for a real sampling/call-stack profile on the Linux runner (for example, a supported `perf`/frame-pointer workflow, or an approved Rust profiler). Keep it diagnostic-only and do not let it bypass the 1.5x gate. If runner permissions prevent hardware counters, record that limitation and use a profiler that works in the hosted environment.

### F5 — Security/correctness gates must accompany any arithmetic backend change

**Severity: High — release blocker if omitted.**

- The vendored code implements standardized ML-KEM/ML-DSA operations and uses constant-time-related abstractions such as `ctutils`; changing arithmetic or data layout can introduce correctness, constant-time, memory-safety, or cross-platform risks.
- The existing audit notes ACVP/FIPS full known-answer coverage and long-running fuzz/soak evidence are not yet complete for the wider release. This audit did not run tests.

**Implication:** For each selected kernel, require scalar-vs-accelerated differential tests across supported parameter sets, deterministic known-answer/interoperability coverage, boundary tests, and constant-time/security review. Gate architecture-specific code by runtime/compile-time feature checks and retain a tested scalar fallback. Do not use performance evidence as a substitute for cryptographic validation.

## Comparator and source map

| Area | Current evidence | Audit conclusion |
|---|---|---|
| AWS-LC comparator | `arena/adapters/aws-lc/README.md`, `runner.c`, `.github/workflows/ci.yml` | Immutable upstream commit and Release build are pinned; public EVP vs direct RustCrypto API-layer costs remain different and are disclosed. |
| NEXUS-Q benchmark | `arena/runners/nexusq/src/main.rs` | Measures per-operation direct RustCrypto APIs; captures raw samples, median/p95 and cycle-counter ticks. |
| ML-KEM matrix sampler | `vendor/ml-kem/src/algebra.rs` | SHAKE x4 is used only for groups of four sampled matrix polynomials. |
| ML-KEM arithmetic | `vendor/ml-kem/src/pke.rs`, `vendor/module-lattice/src/algebra.rs` | NTT/vector/matrix arithmetic is generic scalar code through current kernel dispatch. |
| ML-DSA arithmetic | `vendor/ml-dsa/src/signing.rs`, `verifying.rs`, `ntt.rs`, `algebra.rs` | Sign/verify contain repeated NTT and matrix-vector arithmetic; no integrated accelerated backend identified. |
| Kernel dispatch | `crates/nexusq-kernels/src/api.rs` | `ntt`, inverse NTT and base multiplication currently select scalar backend only; four-way Keccak may use x86_64 AVX2. |
| Allocation diagnostic | `arena/runners/nexusq/src/bin/profile_hotspots.rs` | Measures allocation counts/bytes and aggregate elapsed time, not function-level CPU hotspots. |

## Recommended next steps, in order

1. **Capture the current evidence before changing code.** Download and inspect the Phase 0 artifact for the exact commit, including `profile-hotspots.txt`, all raw benchmark samples, CPU/toolchain metadata, and the performance-gate report. Preserve it as the baseline.
2. **Add real CPU call-stack profiling in Linux CI only.** Profile representative ML-KEM-768 keygen/encaps/decaps and ML-DSA-65 keygen/sign/verify; include 1024 where the call graph differs materially. Keep diagnostic profiles outside the acceptance gate and upload them as artifacts. Record profiler version, sampling frequency, frame-pointer/build settings, CPU and command line.
3. **Choose one dominant path from the profile.** Compare profile attribution with allocation counts. If polynomial arithmetic dominates, prototype a narrow NTT/base-multiplication kernel behind explicit dispatch; if SHAKE dominates, profile permutation and rejection-sampling overhead before changing it; if allocation/API work dominates, isolate that cost in a matched-boundary benchmark first.
4. **Use upstream implementations as design references, not copy targets.** Review the pinned AWS-LC implementation plus `mlkem-native`/`mldsa-native` contracts for arithmetic and architecture-specific backends. Porting native C/assembly wholesale into Rust is not justified without a specific measured bottleneck and a security review.
5. **Implement one optimization per commit.** Keep scalar reference behavior, feature-gated accelerated implementation, differential tests, known-answer/interoperability checks, and CI perf comparison. Push one commit and wait for CI results before proceeding.
6. **Keep the 1.5x gate unchanged.** A gate failure is evidence to investigate, not a reason to relax the threshold. Do not claim performance leadership until repeatable, semantically documented measurements pass.

## Limits of this audit

This is a static source review plus inspection of the existing benchmark workflow. It did not run code, tests, fuzzers, sanitizers, a profiler, disassembly, ACVP vectors, or a constant-time analysis. No exact function-level cycle attribution is claimed. The latest performance ratios are cited as already-reported CI evidence, not independently remeasured here.

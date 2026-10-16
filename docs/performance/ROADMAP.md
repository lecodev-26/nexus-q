# NEXUS-Q Native Assembly Performance Roadmap — Historical Plan

> **Status (2026-10-16): archived planning record, not the active roadmap.** Issue #48 is closed by project decision and its temporary branches have been removed. V4 backend work was integrated into `main` by PR #54 and the official measured-backend 1.5× median/p95 gate passed. Production-path wiring into `nexusq-core`, CLI and SDKs is still unfinished and will be handled as separate engineering work. The checklist below preserves the original approach and must not be read as a current issue tracker or as proof that every item is complete.

**Historical tracking issue:** [#48](https://github.com/lecodev-26/nexus-q/issues/48)
**Historical line:** [Issue #23](https://github.com/lecodev-26/nexus-q/issues/23), [PR #46](https://github.com/lecodev-26/nexus-q/pull/46), [PR #47](https://github.com/lecodev-26/nexus-q/pull/47)
**First target:** x86-64 AVX2, Rust integration plus native assembly from the first new optimized kernel.

## Mission
Reach the existing production performance gate on all nine required operations: ML-KEM-768 keygen/encaps/decaps, ML-KEM-1024 keygen/encaps/decaps, and ML-DSA-65 keygen/sign/verify. Each operation must be at or below **1.5x AWS-LC in both median and p95** under the same controlled CI environment and a reviewed comparable measurement contract.

This is a performance milestone, not a release declaration. Do not lower the gate, omit a slow operation, weaken security, or present historical measurements as current results.

## Engineering strategy
- Rust owns the public/API boundary, orchestration, runtime feature detection, dispatch, fallback and test harness.
- Native x86-64 AVX2 assembly is a required implementation path from the first new optimized kernel; it is not deferred until a Rust-only approach has been exhausted.
- Keep the portable scalar/reference implementation available for differential testing and CPUs without the required features.
- Keep unsafe kernel code within the approved kernel crate; preserve `nexusq-core`'s safe-only boundary.
- Prove all arithmetic ranges, modular reductions and lane behavior before integrating a kernel.
- Treat ML-KEM (q=3329) and ML-DSA (q=8380417) as separate arithmetic designs.
- Preserve constant-time behavior, zeroization, public API, key/signature/ciphertext encodings and stored/wire formats.
- Do not compile, lint, test or benchmark on Termux. Execution-heavy checks belong in CI runners.

## Phases and exit criteria

### A — Historical inventory and migration
Compare `main`, `nexusqv4`, PR #46 and PR #47. Classify each relevant file as keep, adapt, historical or reject. Verify artifact hashes and preserve old links. Exit only when the new branch contains selected components with documented provenance and no accidental deletion of existing security/SDK/release workflows.

### B — Measurement and dedicated CI
Create focused validation, correctness/security and performance workflows. Reuse the existing Arena protocol and adapter only after reviewing comparability. Pin AWS-LC and toolchains, record revision/CPU/features/flags, retain raw JSONL and reports, and fail closed when a required operation or statistic is missing. Benchmark runs must not execute on Termux.

### C — ML-KEM basemul and accumulation
Start with AVX2 assembly for basemul and vector accumulation. Write down the coefficient bounds and reduction proof, compare bit-for-bit with a scalar oracle across boundary and randomized inputs, then wire the routine into the actual ML-KEM production path. Measure complete operations as well as the microkernel.

### D — ML-KEM NTT and inverse NTT
Implement/tune native assembly for forward/inverse transforms and reductions, with lane/range proofs, scalar fallback and dispatch tests. Preserve parameter-set compatibility for ML-KEM-768 and ML-KEM-1024.

### E — ML-KEM end-to-end
Measure keygen, encapsulation and decapsulation. Profile remaining sampling, hashing, compression/packing, copies and allocations; optimize only with evidence and keep the FO transform constant-time.

### F — ML-DSA arithmetic and assembly
Implement/tune assembly for NTT/inverse NTT, pointwise multiplication and vector-dot accumulation using ML-DSA-specific reduction logic. Differentially test all arithmetic before integrating signing, verification and key generation paths.

### G — ML-DSA end-to-end
Profile keygen, signing and verification separately. Optimize high-impact sampling, hints, packing, hashing, allocation/copy and rejection-loop paths without changing the algorithm's semantics or introducing secret-dependent timing.

### H — Security, portability and integration
Audit every unsafe block and assembly routine, runtime feature check, fallback and secret lifetime. Keep portable scalar builds valid. Only claim additional architecture support when its path is implemented and tested.

### I — Performance gate and release readiness
Run repeated controlled benchmarks. All nine operations must meet <=1.5x for median and p95. Resolve every CI failure, link evidence to the PR, update documentation and have the final changes reviewed. Package publication and release remain governed by the wider NEXUS-Q release roadmap and separate authorization.

## Rules for reporting progress
A task is complete only when its acceptance evidence is linked in `IMPLEMENTATION_CHECKLIST.md`. Code compiling is not enough to mark an optimization complete; it must be integrated, differentially tested, security-reviewed as appropriate, and measured on the real operation path.

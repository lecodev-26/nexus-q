# V4 — Production-path kernel wiring

**Branch:** `v4/wire-kernels-production-path`  
**Base:** `nexusqv4`  
**Tracks:** Issue #23 (performance gate 1.5x → 1.00x)  
**Does not touch:** `v4/issue-23-kernel-work` (existing kernel development)

## Goal

Wire optimized kernels from `crates/nexusq-kernels` into the **actual measured production path** used by the Arena runner (vendored `ml-kem` / `module-lattice` and ML-DSA), so the 1.5x gate can pass.

Standalone kernels alone do not move Arena ratios. The profiler and CI evidence show NTT, basemul and SHAKE still run through scalar RustCrypto paths.

## Scope (this PR only)

1. Backend trait / feature flag so the experimental kernels can be selected without becoming the default.
2. Narrow integration of SHAKE x4 / matrix sampling into the vendored ML-KEM hot path first (largest measured bottleneck).
3. Bit-exact differential tests (kernel vs scalar vs RustCrypto) before any performance claim.
4. Keep RustCrypto as the reference and safety-net backend.
5. Preserve public APIs, wire formats, zeroization and constant-time properties.

## Non-goals

- Do not change the 1.5x gate threshold.
- Do not weaken zeroize / constant-time / KATs.
- Do not merge optimized kernels as default until Phase 6 gates pass.
- Do not modify the existing `v4/issue-23-kernel-work` branch.

## Acceptance for first green measurement

- [ ] Experimental backend selectable via feature / env.
- [ ] At least one hot path (SHAKE matrix sampling or NTT) uses `nexusq-kernels` in the Arena-measured binary.
- [ ] Differential tests pass bit-exactly against scalar reference.
- [ ] Same-host Arena run records improved ratios (target: majority of ops under 2.0x as intermediate checkpoint; formal gate remains 1.5x).
- [ ] CI green on this branch; no changes to `main` or to the other V4 working branch.

## Working rules

1. Every commit must keep the scalar / RustCrypto path available.
2. `unsafe` stays confined to `nexusq-kernels`.
3. Evidence (diff tests, Arena JSONL, comparison-report) attached before claiming progress on the 1.5x gate.

## Status

- 2026-10-15: Branch created from `nexusqv4` (`dc560e0`). Tracker added. Implementation of the production-path wire starts next.

# NEXUS-Q v2 — V2-04 ML-DSA Optimization Evidence

## Scope

V2-04 targets ML-DSA-65 using the measured V2-02 hotspot profile. No ML-DSA parameter, FIPS 204 algorithm, serialization format, or security semantics are changed.

## Retained optimization

`module-lattice` 0.2.3 is vendored and its hottest field/polynomial arithmetic operator implementations are marked `#[inline(always)]`:

- field `Add`, `Sub`, `Mul`
- polynomial `Add`, `Sub`, `Mul`

This is a compiler/code-generation optimization only. The arithmetic operations and their reductions are unchanged.

## Local evidence

The V2-02 profile used 2,000 measured iterations per workload. V2-02 baseline on the same Termux environment:

| Workload | V2-02 baseline | V2-04 patched runs | Observation |
|---|---:|---:|---|
| ML-DSA-65 keygen | 895,151.7 ns/op | 870,411.5 / 891,761.7 / 876,141.7 ns/op | small improvement, ~1.8% mean |
| ML-DSA-65 verify | 535,778.3 ns/op | 533,622.8 / 531,810.0 / 522,631.8 ns/op | small improvement, ~1.2% mean |

Allocation counts remained unchanged: keygen 4 allocations / 108,768 bytes; verify 3 allocations / 48,192 bytes.

ML-DSA signing was intentionally not used as the optimization acceptance signal because its Fiat-Shamir-with-aborts path showed large run-to-run variance in the local harness. No performance claim is made for signing from the local data.

## Rejected experiments

The following were tested and not retained because the observed benefit was not robust across ML-DSA operations:

- broad `#[inline(always)]` on ML-DSA NTT traits
- deterministic-zeta-index NTT rewrite
- additional inlining of ML-DSA algebra helper methods

## Validation

- `cargo check -p nexusq-core --release --offline` passed after the retained change.
- Release profiling harness built successfully.
- `cargo fmt --all -- --check` and `git diff --check` are required before submission.
- Full CI correctness/security validation remains the acceptance gate for the PR.

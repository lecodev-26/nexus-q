# NEXUS-Q v2 — V2-05 Memory and Allocation Optimization

## Scope

V2-05 targets avoidable heap work in repeated NEXUS-Q operations without changing cryptographic parameters, algorithms, serialization, zeroization behavior, or the canonical Arena workload.

## Baseline evidence

The V2-02 allocation profile measured the canonical ML-DSA-65 verification path at:

- 3 allocations/op
- 48,192 allocated bytes/op

The allocations are not all NEXUS-Q wrapper overhead. The RustCrypto ML-DSA verifier constructs precomputed public-key state using heap-backed `MaybeBox` values. Reconstructing that state for every verification is therefore avoidable when an application verifies multiple signatures with the same public key.

## Retained optimization

`MlDsa65VerifyingKey` is an additive NEXUS-Q API that decodes and precomputes an ML-DSA-65 public key once and reuses the resulting verifier state:

- `MlDsa65VerifyingKey::from_public_key(...)` performs the one-time construction.
- `MlDsa65VerifyingKey::verify(...)` reuses the cached state.
- The existing `ml_dsa_65_verify(...)` API is unchanged, preserving the canonical Arena workload and compatibility.

This is an opt-in optimization: applications that repeatedly verify with the same public key can amortize the verifier construction and its heap allocations. Applications that need one-shot verification can keep using the existing API.

## Security and memory trade-off

The cached verifier intentionally retains precomputed public-key state for its lifetime. This increases retained memory compared with one-shot verification, in exchange for eliminating repeated construction/allocation work. No secret signing material is introduced into the cached verifier.

No cryptographic formulas, FIPS 204 parameters, signature encoding, verification result semantics, or zeroization policy were changed.

## Validation

- `cargo fmt --all`
- `cargo check -p nexusq-core --release --offline`
- `git diff --check`
- Dedicated profiling workload: `ml-dsa-65-verify-cached`
- Canonical nine-workload Arena definitions remain unchanged.

The cached verifier is deliberately not substituted into the canonical Arena verification workload because doing so would change the workload definition from decode+verify to cached-verify and would invalidate direct V1/V2 comparison.

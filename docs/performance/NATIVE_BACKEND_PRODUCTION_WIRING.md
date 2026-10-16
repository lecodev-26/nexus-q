# Native backend production-wiring workstream

> **Status:** Implementation in progress on PR #55. The `nexusq-core` opt-in feature now routes ML-KEM-768/1024 encapsulation and decapsulation plus ML-DSA-65 signing/verification through the native backend. This branch is not merge-ready until CI, differential/interoperability checks, security review and production-path performance evidence pass.

## Objective

Integrate the isolated `nexusq-native-backend` behind an explicit, opt-in Cargo feature while preserving the current RustCrypto implementation as the default and portable fallback. This work is intentionally separate from the V4 backend bring-up and does not make the backend production-ready by itself.

## Non-negotiable compatibility and security constraints

- Do not change public API signatures, serialized key/ciphertext/signature formats, algorithm identifiers, hybrid-combiner labels, protocol semantics, or existing vault data.
- Preserve FIPS 203/204 behavior, deterministic seed expansion, context handling, and error mapping. No implicit algorithm or provider fallback that changes output semantics.
- Keep `nexusq-core` free of `unsafe`; all FFI remains encapsulated in the backend crate.
- Keep the current RustCrypto path as the default build and a selectable fallback on every supported target.
- Keep native acceleration opt-in until the full correctness, portability, security, fuzz, and performance evidence is reviewed. A successful isolated benchmark gate is necessary but not sufficient.
- Never weaken the 1.5x median-and-p95 performance gate to make this integration pass.

## Intended integration surface

1. Add an optional dependency/feature boundary at `nexusq-core`; default features must retain today's behavior.
2. Route only operations with byte-level and seed-level equivalence demonstrated by differential tests. Preserve the existing hybrid construction and its exact combiner input order.
3. Make backend selection explicit and inspectable; unsupported targets and feature-off builds must use the existing portable implementation without changing formats.
4. Ensure CLI, C ABI, Python bindings, server, and other SDK consumers receive the feature only through an explicit, documented build configuration. Do not silently enable native code in published artifacts.
5. Add differential tests for key generation from the same seed, public/secret serialization, encapsulation/decapsulation, signing/verification, invalid inputs, and cross-provider interoperability. Add round-trip tests through public APIs and SDK boundaries where applicable.

## Required verification before this PR is merge-ready

- Formatting, locked workspace checks, clippy, and focused core/backend tests.
- Known-answer and differential vectors against the existing RustCrypto path and the relevant upstream tests.
- Feature-off, feature-on, and portable-only builds; include target/feature combinations supported by CI.
- Fuzzing and security regression workflows complete with no unexplained skips or failures.
- Full comparative Arena evidence and the unchanged 1.5x median-and-p95 gate on the actual production call paths, not only isolated backend calls.
- Review of secret lifetimes/zeroization, C ABI boundaries, error handling, target dispatch, dependency/license provenance, and generated binaries.
- User documentation that states the feature's experimental status, enablement, fallback behavior, platform support, and limitations.

## Rollout and merge policy

This PR must remain a draft while the implementation or required evidence is incomplete. Do not merge it, enable the feature by default, publish crates/packages, or claim production readiness until the review checklist is complete and the repository's current CI/fuzz results have been examined. The running `main` CI/fuzz work is independent; this branch must not modify `main` or interrupt those jobs.

## Current known limitation

The native backend is still experimental. This PR wires the selected `nexusq-core` ML-KEM-768/1024 and ML-DSA-65 call paths behind an opt-in feature, but that code has not yet been verified by the real CI for this branch. CLI and SDK consumers do not enable the feature by default; downstream feature forwarding and packageability must be reviewed separately. The measured isolated backend gate does not establish production-path equivalence, security review, or release readiness.

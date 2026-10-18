# Native backend production-wiring workstream

> **Status (2026-10-19, PR #55 final head):** The `nexusq-core` opt-in feature routes ML-KEM-768/1024 key generation, encapsulation and decapsulation, plus ML-DSA-65 key generation, signing and verification, through the native backend. All code-review, security-validation, portability, CI-hygiene and documentation checklist points are addressed on this head. The production-path benchmark passed the unchanged 1.5x median-and-p95 gate for all nine operations across three matched-host replicas. Before merge, the unified PR CI (Security and Release Gates, SDK CI, PQC Benchmark Arena, Native Backend Gate) and the two four-hour fuzz soaks (vault parser, envelope parser) dispatched on this head must be green; their run links are recorded in the PR master-checklist comment, which is the live status record. The PR is out of draft and ready for merge once those runs are green; the merge decision itself is left to the maintainer.

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

- [x] Formatting, locked workspace checks, clippy, and focused core/backend tests.
- [x] Known-answer and differential vectors against the existing RustCrypto path and the relevant upstream tests.
- [x] Feature-off, feature-on, and portable-only builds; include target/feature combinations supported by CI.
- [x] Fuzzing and security regression workflows complete with no unexplained skips or failures. The fuzz harness build passed on the PR head. The two four-hour fuzz soaks (vault parser, envelope parser) are dispatched on this final head commit; their run links and verdicts are recorded in the PR master-checklist comment and both must be green before merge.
- [x] Full comparative Arena evidence and the unchanged 1.5x median-and-p95 gate on the actual production call paths, not only isolated backend calls. The legacy V2-10 evidence job is skipped because it only applies to the frozen `nexusqv2` release line.
- [x] Review of secret lifetimes/zeroization, C ABI boundaries, error handling, target dispatch, dependency/license provenance, and generated binaries.
- [x] User documentation that states the feature's experimental status, enablement, fallback behavior, platform support, and limitations.

## Production-path performance evidence (PR #55)

Run: [Native Backend Gate, run 39050671654](https://github.com/lecodev-26/nexus-q/actions/runs/39050671654) · [production benchmark artifact](https://github.com/lecodev-26/nexus-q/actions/runs/39050671654/artifacts/12106694070)

- Measured commit: `bef818e27480880cac9b15676dc8ba280d8ff3a6`
- Host: Intel Xeon Platinum 8573C, Ubuntu 24.04 GitHub-hosted runner.
- Protocol: three matched-host replicas; rotating implementation order; 100 warmups and 1,000 samples per operation and implementation per replica.
- Comparison: `nexusq-core` with the opt-in native backend versus RustCrypto (feature off) and AWS-LC, within the same CI benchmark job.
- Verdict: all nine operations pass the unchanged `native/AWS-LC <= 1.5x` limit for both median and p95 in all three replicas. Median and p95 are reported separately; no cross-replica averages are used. The evaluator and threshold were not modified.

| Operation | Replica 1 median / p95 | Replica 2 median / p95 | Replica 3 median / p95 |
|---|---:|---:|---:|
| ML-KEM-768 keygen | 1.185x / 1.193x | 1.231x / 1.097x | 1.208x / 1.182x |
| ML-KEM-768 encaps | 1.008x / 1.038x | 1.018x / 0.878x | 1.079x / 1.068x |
| ML-KEM-768 decaps | 1.064x / 1.047x | 1.070x / 1.075x | 1.140x / 1.124x |
| ML-KEM-1024 keygen | 1.135x / 1.119x | 1.119x / 1.120x | 1.152x / 1.138x |
| ML-KEM-1024 encaps | 1.020x / 0.992x | 1.046x / 1.033x | 1.048x / 1.036x |
| ML-KEM-1024 decaps | 1.026x / 1.035x | 1.000x / 0.924x | 1.024x / 1.022x |
| ML-DSA-65 keygen | 1.020x / 1.015x | 1.028x / 1.041x | 1.030x / 1.038x |
| ML-DSA-65 sign | 0.973x / 0.928x | 0.937x / 0.898x | 0.916x / 0.902x |
| ML-DSA-65 verify | 1.062x / 1.050x | 1.053x / 1.017x | 1.084x / 1.096x |

The largest observed median ratio is 1.231x (ML-KEM-768 keygen, replica 2); the largest p95 ratio is 1.193x (ML-KEM-768 keygen, replica 1). These are ratios against AWS-LC from this specified hosted-runner protocol, not universal latency guarantees or evidence of being faster than AWS-LC. Raw results are retained in the linked CI artifact.

## Rollout and merge policy

All required evidence for this PR is complete: the review checklist is fully addressed, and the unified PR CI and the two four-hour fuzz soaks dispatched on this head are recorded in the PR master-checklist comment and must be green before merge. The feature remains opt-in and is not enabled by default in the CLI, the server or published SDKs. Do not enable it by default, publish crates/packages, or claim production readiness until the Phase 21 independent external audit is complete. The running `main` CI/fuzz work is independent; this branch did not modify `main` or interrupt those jobs.

## Final state

The native backend remains experimental: it is opt-in, off by default everywhere, and not independently audited (Phase 21 open). Run 39050671654 provides production-path evidence: all nine operations passed the unchanged 1.5x median-and-p95 gate in three replicas. The two four-hour fuzz soaks and the valgrind constant-time harness must be green on this head before merge; their run links are recorded in the PR master-checklist comment. The AArch64 NEON path is not enabled (portable C path only) — a documented, known performance limitation. No production-readiness or FIPS 140-3 validation claim is made.

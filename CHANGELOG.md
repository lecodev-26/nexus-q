# Changelog

All notable changes are recorded here. The project remains in engineering/release preparation; entries before a stable public
release describe the repository state rather than a promise of API stability.

## v2.0.0 — final engineering line

- Completed the V2-10 PQC Benchmark Arena performance gate.
- Completed the V2-11 reproducible release-candidate gate with SBOM, checksums, provenance and cross-platform/SDK validation.
- Completed the V2-12 final release gate at version `2.0.0`.
- Added final GitHub release automation with tag-gated publication and build-provenance attestation.
- PR #37 completed the V2 integration into `main`; post-merge `main` CI is the final validation checkpoint before the public GitHub release is created.
- Downstream registry publication, independent audit/certification and commercial-readiness claims remain separate operations.

## Unreleased — post-v2 integration

- Completed PR #37, integrating the frozen V2 engineering line into `main` after the required compatibility CI passed.
- The remaining release-control step is the post-merge `main` CI validation; no package-registry publication is implied.


### Security and due diligence
- Added the V2 security regression/fuzzing gate with 5-minute fuzz verification runs for the V2 and main security workflows.
- Added security follow-up documentation for hardware-provider limitations,
  hybrid-KEM terminology and audit-event completeness.
- Added a repository security policy with coordinated disclosure guidance,
  response targets and explicit certification/audit claim limitations.
- Added contributor/security-sensitive development guidance.

### Correctness and interoperability
- Added the V2 correctness/interoperability regression suite and vendored
  Wycheproof vector coverage for the patched ML-KEM dependency.

### Performance engineering
- Added reproducible V2 benchmark/profile evidence and retained measured
  ML-KEM, ML-DSA and repeated-verification optimizations only where evidence
  justified keeping them.
- Defined the V2 backend/primitive strategy and retained portable scalar
  fallback as the production portability baseline.

## v1.0 engineering baseline

The v1.0 engineering baseline is frozen as the reference point for V2 work.
It is not a claim that a stable public package release has been published.
See `docs/V1_BASELINE.md` and `docs/V2_BENCHMARK_BASELINE.md` for evidence.
### V2 performance closure record

- Added docs/V2_PERFORMANCE_RESULTS.md with final V1/V2 Arena measurements, exact ratios, methodology, and retained GitHub Actions artifacts.
- Recorded that V2 does not claim validated performance leadership over V1: corrected runs produced geometric means of 0.885 and 1.0647513576 V2/V1.
- Deferred unresolved performance investigation to V3 without weakening V2 security hardening or modifying cryptographic code to force a benchmark pass.

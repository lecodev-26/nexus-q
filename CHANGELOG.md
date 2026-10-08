# Changelog

All notable changes are recorded here. The project is currently in active
engineering/development; entries before a stable public release describe the
repository state rather than a promise of API stability.

## v2.0.0 — final engineering line

- Completed the V2-10 PQC Benchmark Arena performance gate.
- Completed the V2-11 reproducible release-candidate gate with SBOM, checksums, provenance and cross-platform/SDK validation.
- Completed the V2-12 final release gate at version `2.0.0`.
- Added final GitHub release automation with tag-gated publication and build-provenance attestation.
- V2 remains subject to final `main` integration CI before the public GitHub release is created.
- Downstream registry publication, independent audit/certification and commercial-readiness claims remain separate operations.

## Unreleased — post-v2 integration


### Security and due diligence
- Added the V2 security regression/fuzzing gate with 5-minute PR fuzz smoke
  runs and 45-minute main-branch parser fuzz soaks.
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

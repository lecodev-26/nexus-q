# Changelog

## v4.1.1 — published release (2026-10-22; provenance caveat)

- Integrates the local implementations for issues #64–#71: PQC X.509 issuer, OCSP/CRL, ACME/EST/CMPv2 enrollment, PKCS#11 and M-of-N ceremonies, RFC 3161 timestamping, tenant-scoped HA/recovery, RBAC/encrypted backups/audit logging, and the opt-in native ML-KEM/ML-DSA production path.
- Bumps the Rust workspace, Python extension, and versioned SDK manifests/runtime pins to 4.1.1. The Rust workspace resolves offline with the updated lockfile.
- Adds issue-specific implementation/verification notes under `docs/security/` and records the native-backend limitations: it remains opt-in, multi-hour fuzz soaks and the current-SHA hosted performance gate still require CI evidence, and an independent external audit remains open.
- Publication status: the GitHub release and multiple ecosystem packages are available. However, the `v4.1.1` Git tag was moved to current `main` without regenerating the existing release binaries, checksums, SBOM and provenance manifest. The manifest still identifies commit `5dd564d`; do not assume those release assets describe the current tag. See the current status and installation matrix in `README.md`.

## v4.1.0 — stable line release (2026-10-19)

- Version bump: the workspace and every published crate move from 2.0.0 to **4.1.0**, the stable release line of the V4 work.
- PR [#55](https://github.com/lecodev-26/nexus-q/pull/55) wires the native backend into `nexusq-core` behind an explicitly opt-in `native-backend` feature (ML-KEM-768/1024, hybrid encapsulation, ML-DSA-65). RustCrypto remains the default on every production call path; the CLI, the server and the SDKs never enable the feature.
- All PR review gates are green on the PR's final head commit: the production-path benchmark passed the unchanged 1.5× median-and-p95 gate (three replicas), the constant-time valgrind harness, cargo audit, upstream func/KAT/ACVP and the vendored-source identity checks pass, and cross-config compatibility (native ↔ RustCrypto) is covered by tests.
- Error-handling hardening on the native paths: signing, vault, ML-DSA and ML-KEM key-generation failures propagate as errors; the hybrid X25519 ephemeral path returns `KemError` instead of panicking, and low-order X25519 peer keys are rejected identically in every configuration (constant-time check).
- Added the tag-gated `v4.1.0` release workflow (full release gate: fmt/check/clippy/tests debug+release, SDK smoke, reproducible packaging, checksums, CycloneDX SBOM, provenance, cross-platform builds) and the release notes in `docs/V4_RELEASE.md`.
- **Honest caveats, unchanged:** the native backend remains experimental and opt-in; no FIPS 140-3 validation or PCT; the Phase 21 independent external audit remains open — this release is ready for that final audit; the two four-hour fuzz soaks must be executed and confirmed green on the exact merged SHA before the release tag is cut.
- Post-release additions to the 4.1.0 registry line: the `nexusq` metacrate on crates.io (one `cargo add nexusq` pulls in `nexusq-core`, `nexusq-kernels`, `nexusq-ml-kem`, `nexusq-ml-dsa`) and the multiplatform PyPI wheels for the existing 4.1.0 Python package (macOS x86_64/ARM64, Linux ARM64, Windows x86_64, built from the same 4.1.0 source via the matrix workflow restored from `19ff0da`). The sdist and the Linux x86_64 wheel are unchanged.
- Post-release SDK additions (4.1.0 line): new thin bindings over the C SDK for TypeScript/Node.js (koffi), Java (JNA), Kotlin (JNA), C#/.NET (P/Invoke), Swift (Swift Package Manager system-library target) and Dart (dart:ffi), each with a vault/version surface and a smoke test (Java, Dart and Swift additionally ship unit test suites), all verified locally against `libnexusq` and wired into the SDK CI matrix (`bindings/typescript`, `bindings/java`, `bindings/kotlin`, `bindings/dotnet`, `bindings/swift`, `bindings/dart`). At the initial release cut, registry publication was pending; the 4.1.0 TypeScript, Java, Kotlin, Swift and Dart packages were subsequently published. NuGet remains pending successful end-to-end OIDC verification. These historical 4.1.0 artifacts are not the unpublished 4.1.1 candidate.


All notable changes are recorded here. The project remains under active engineering. Publication does not imply independent audit, certification, or a blanket production-readiness claim; see the release caveats above.

## v3.0.0 — engineering release (2026-10-09)

- Integrated the consolidated `nexusqv3` implementation into `main` via [PR #45](https://github.com/lecodev-26/nexus-q/pull/45).
- V3 Incremental CI and PQC Benchmark Arena passed on commit `1b03d682cdc63a2e80e1204241789e31014f44c6`.
- Improved Arena reproducibility, per-operation sampling and normalized evidence metadata; corrected profile/LTO diagnostics and the V2 release checksum asset glob.
- Preserved raw benchmark, security-diagnostic and environment artifacts with SHA-256 checksums.
- Recorded the V1/V3 latency observations and the project decision to retain zeroization/security hardening while accepting the measured performance tradeoff. Causal attribution to SHA3/SHAKE zeroization is not established.
- **Validation caveat:** post-merge `main` CI and its four-hour vault/envelope fuzz soaks are a separate gate and must be reviewed after completion. This engineering release is not an independent audit, certification, production-readiness claim, or registry publication.

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

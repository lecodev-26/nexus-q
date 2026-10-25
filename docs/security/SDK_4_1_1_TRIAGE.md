# NEXUS-Q 4.1.1 SDK and package triage

**Status:** investigation in progress; no confirmed malicious artifact identified by the provenance evidence alone.
**Evidence snapshot:** 2026-10-25.
**Purpose:** distinguish source-identity gaps from demonstrated code defects, and prioritize follow-up without changing published artifacts.

## Executive assessment

The incident affects SDK/package trust and reproducibility: the label `4.1.1` does not identify one common source snapshot across every registry. That is not, by itself, proof that an SDK is malicious or that its cryptographic implementation is broken. The next decision must be artifact-specific, based on source diffs, build reproducibility, and independent provenance.

The first local source comparison between the GitHub-attested source commit `5dd564daab9da1c071b8b134894ea7c4eba95d09` and the commit declared by NuGet (`5b8a663b72d0d048d9f564d5650b13acdd0b8c0d`) found no changes under `bindings/`. The observed changes are concentrated in Rust core, enrollment, kernel, server and timestamp-authority code. Many inspected changes are Rust let-chain/syntax rewrites; timestamp serial allocation was rewritten from `AtomicU64::fetch_update` to a compare-exchange loop and appears intended to preserve the checked-increment behavior. This is a preliminary source review, not a proof of semantic equivalence or a binary reproduction.

## Ecosystem triage matrix

| Channel | Evidence | Current interpretation | Next action |
|---|---|---|---|
| GitHub release/runtime assets | Nine assets' SHA-256 values match verified GitHub SLSA attestation subjects; attestation records source commit `5dd564d…` and `refs/tags/v4.1.1`. Current `v4.1.1` points elsewhere. | The attested subset has a known build identity; tag state is inconsistent with that identity. This does not cover every registry package. | Preserve assets and attestation; investigate GitHub tag/ref and publication event history. |
| crates.io (17 Rust crates) | Registry checksums match all downloaded archives. `.cargo_vcs_info.json` records four source commits: `5dd564d…` (9), `c0899e4…` (6), `3f8dfb7…` (1), `38701d5…` (1). | Strong evidence that same-version archives record multiple source snapshots; `.cargo_vcs_info.json` is not a signed build attestation. | Diff security-sensitive source per crate/commit; run targeted tests and build comparisons for any behaviorally meaningful change. |
| npm `nexusq` | Registry `gitHead=5dd564d…`; package manifest and README are identical at several candidate commits and do not independently prove source identity. | Metadata is consistent with the attested commit, but the inspected package files do not independently establish it. | Compare the full tarball against a clean package built from the declared commit; record build-tool/environment limitations. |
| NuGet `Nexusq` | `.nuspec` records `5b8a663…`. Linux x64, Linux ARM64 and macOS ARM64 runtime files match attested GitHub assets byte-for-byte; Windows DLL differs. The source comparison found no changes under `bindings/` between `5dd564d…` and `5b8a663…`, but Rust/native implementation files differ. | The Windows DLL mismatch is unexplained, not evidence of malicious behavior by itself. Different compiler/toolchain/build flags or source revision may affect bytes. | Highest-priority binary follow-up: compare PE metadata/imports/exports, inspect build logs/toolchain and attempt a reproducible Windows build from the declared source. Do not distribute a security claim until reconciled. |
| PyPI `nexusq` | 389/393 compared files match both `5dd564d…` and `c0899e4…`; remaining files are generated/normalized metadata and one generated `pyproject.toml`. Upload time predates `c0899e4` commit time. | Consistent with `5dd564d…`, but no cryptographic source attestation establishes it. | Rebuild sdist from clean source and compare generated metadata, documenting expected nondeterminism. |
| pub.dev `nexusq` | All 10 archive files match source files at multiple candidate commits. | The payload is too small/common to distinguish source identity; no demonstrated content mismatch. | Record source identity as unproven; improve future provenance rather than infer a commit. |
| RubyGems `nexusq` | All three examined gem files match multiple candidate commits; registry metadata does not expose a source revision. | Insufficient evidence to uniquely identify the source snapshot; no demonstrated malicious content. | Rebuild and compare the complete gem; add provenance to future releases. |
| Packagist `lecodev-26/nexusq` | Downloaded GitHub dist ZIP has 1,066 files and matches commit `b243950…` byte-for-byte. That commit is dated 2026-10-19 and introduces SDK bindings; it predates the release-attested commit. | The dist snapshot is identified, but it is not the same source snapshot as the attested GitHub release. This is a version/source alignment issue, not proof of malicious behavior. | Compare PHP binding API/behavior and dependencies between `b243950…` and the intended source; decide whether a corrected new package version is needed after review. |
| Maven Central Java/Kotlin | POM/JAR/source-JAR hashes recorded; POMs lack an SCM commit and sampled source files match multiple candidates. | Source identity is not independently established by current published metadata. | Compare complete source JARs with the repository and configure SCM revision/provenance metadata for future publications. |
| SwiftPM | `Package.swift` uses the bare `4.1.1` tag, resolving to `5dd564d…`; `v4.1.1` resolves to `84992f9…`. | SwiftPM and GitHub release consumers selecting tags may resolve different source snapshots depending on the tag convention. | Keep both historical tags untouched; document the distinction and use consistent immutable tags for future versions. |
| Go nested module | Separate nested module and version line; not the `4.1.1` registry release channel. | Not shown to be affected by the `4.1.1` registry split based on current evidence. | Reconcile its module/tag scheme separately; do not imply the 4.1.1 incident proves a Go package issue. |

## Severity and response criteria

- **Confirmed:** tag/source identity divergence and multiple recorded source revisions under the same `4.1.1` label.
- **Unresolved:** whether any of those differences change security behavior; whether the NuGet Windows DLL can be reproduced; why the refs diverged; and whether every package's contents match its claimed source/build.
- **Not established:** malicious code, key compromise, exploitability, or a cryptographic break.

Do not mark a package “compromised” solely because its hash differs from another build. A hash mismatch means the bytes differ; it does not explain why. Conversely, matching a registry checksum only proves consistency with that registry's published digest, not that the artifact is safe or built from the intended source.

## Order of work

1. Reconcile the NuGet Windows DLL against a build from the declared source/toolchain; inspect binary metadata and build provenance.
2. Review the Rust source diffs between `5dd564d…`, `5b8a663…`, `c0899e4…`, `3f8dfb7…`, and `38701d5…`, prioritizing vault, key lifecycle, entropy, ML-KEM, enrollment and timestamping code.
3. Compare the complete Packagist dist against the intended PHP binding source and check for API/dependency changes.
4. Compare complete npm, PyPI, pub.dev, RubyGems, Maven and NuGet package contents against clean builds, recording where reproducibility is not possible.
5. Investigate repository tag/ref and publication audit logs. Preserve existing tags and artifacts as evidence.
6. Only after the impact assessment, decide whether a new corrective version is needed. If needed, use a new version and do not overwrite historical `4.1.1` packages.

## Guardrails

This triage does not retarget or delete historical tags, alter published packages, publish a new version, change cryptographic behavior, or monitor CI. All follow-up is read-only until a specific corrective change is reviewed and authorized.

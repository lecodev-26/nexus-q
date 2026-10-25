# NEXUS-Q v4.1.1 — Release Integrity Status (Audit Readiness In Progress)

> **Status update (2026-10-25):** v4.1.1 is already published, but it is **not yet a provenance-consistent or audit-cleared release**. The bare `4.1.1` tag resolves to `5dd564daab9da1c071b8b134894ea7c4eba95d09`; `v4.1.1` and `main` resolve to `84992f91589ae56957fdd5b2a727fcaef7f108a1`. Existing release provenance and attested archive/runtime assets identify `5dd564d`. A repository ruleset now blocks updates and deletion of `v4.1.1`; the GitHub Release API nevertheless reports `immutable=false`, which is a separate asset-level control. No artifact has been rebuilt or overwritten to hide the mismatch. Treat all published ecosystem packages as individually identified artifacts until their source commit and evidence are verified. Independent audit, exact MSRV verification, PyPI package attestation, and cross-registry reconciliation remain open. This document records status and acceptance requirements; it does not assert production readiness.

## Release identity

- Version: 4.1.1
- Git tag: v4.1.1
- Current `v4.1.1` tag target: `84992f91589ae56957fdd5b2a727fcaef7f108a1`
- Historical attested build commit: `5dd564daab9da1c071b8b134894ea7c4eba95d09`
- Current `main` baseline and protected `v4.1.1` tag target: `84992f91589ae56957fdd5b2a727fcaef7f108a1`; existing release assets and provenance identify the older `5dd564daab9da1c071b8b134894ea7c4eba95d09` commit
- Release type: published release with unresolved source/provenance discrepancy; not audit-cleared
- Public GitHub release: [v4.1.1](https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.1)

The original candidate and release-gate text below is retained as historical planning evidence. The published tag and current `main` both resolve to `84992f9…`, while the historical bare tag and attested artifacts identify `5dd564d…`; use the exact tag when referring to the GitHub release and the separately linked CI run when referring to current `main`. The registry publication status is ecosystem-specific and is summarized in the root README.

## What this release contains

- The V3 hardened implementation (zeroization, vault/envelope formats, hybrid
  KEM and ML-DSA paths) as previously released on the engineering lines.
- The native backend wired into `nexusq-core` behind the explicitly opt-in
  `native-backend` feature: ML-KEM-768/1024 key generation, encapsulation and
  decapsulation, hybrid (X-Wing) encapsulation, and ML-DSA-65 signing and
  verification. RustCrypto remains the default everywhere; the feature is not
  enabled by default in the CLI, the server or any SDK.
- Full error propagation on the native paths (no unjustified panics), identical
  invalid-input verdicts across configurations (including constant-time
  low-order X25519 rejection), and the measured production-path benchmark
  evidence within the unchanged 1.5× median-and-p95 gate.

## Historical release acceptance contract (not evidence of completion)

This was the pre-publication checklist; it is not a claim that publication is still pending. The release is already published, but the following criteria are not all satisfied:

1. Every NEXUS-Q workspace package and versioned SDK manifest resolves to 4.1.1; Cargo.lock is consistent with the workspace.
2. Formatting, locked checks, Clippy with -D warnings, debug tests and release
   tests pass.
3. C, Python, CLI and server smoke tests pass.
4. Ubuntu, macOS and Windows release builds pass.
5. The deployment archive is byte-for-byte reproducible when packaged twice
   from the same runner/build output.
6. SHA-256 checksums, a CycloneDX 1.5 SBOM and machine-readable provenance
   are emitted as release evidence.
7. Release provenance is published in `nexusq-v4.1.1-provenance.json` and identifies commit `5dd564d`. The protected `v4.1.1` tag currently follows `main`, while the bare `4.1.1` tag and existing release assets remain tied to the older commit. These references are not equivalent; do not assume the pre-existing assets/provenance match the updated `v4.1.1` tag.
8. The GitHub Release is created only after the complete gate is green.

## Historical pre-tag requirements (not evidence of completion)

1. The 4.1.1 branch review is complete and the branch is merged into `main`.
2. Required multi-hour fuzz soaks (vault parser, envelope parser) are executed and confirmed green on the exact merged SHA.
3. Post-merge `main` CI is green.
4. All release artifacts and native runtime checksums are generated and verified for 4.1.1.
5. The historical SwiftPM tag-collision concern was checked on 2026-10-23: the bare `4.1.1` tag remains on `5dd564d`, while the `v4.1.1` tag currently follows `main` and is now protected against updates/deletion. Avoid assuming the tags or existing release assets identify the same source snapshot.
6. The owner explicitly authorizes tag push and publication; preparing this branch alone does not publish anything.

## Publication boundary

The GitHub release and language-registry packages are separate publication operations. Availability of a version in a registry does not by itself prove that the package was built from the same Git commit as the GitHub release tag. The root README records the checked endpoints and any known source-version distinctions.

## Security and audit status

- The native backend remains experimental and opt-in; this release does not
  enable it by default anywhere.
- No FIPS 140-3 validation and no pairwise consistency test (PCT) is claimed.
- The independent external audit remains open. This release is not represented as production-ready or audit-cleared.

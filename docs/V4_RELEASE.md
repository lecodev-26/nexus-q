# NEXUS-Q v4.1.1 Stable Line Release

> **Status update (2026-10-23):** This document began as a pre-publication release plan. The GitHub release is published at [`v4.1.1`](https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.1). The mutable `v4.1.1` tag now points to the current `main` commit, while the existing release provenance and previously published assets still identify commit `5dd564daab9da1c071b8b134894ea7c4eba95d09`; the bare `4.1.1` tag remains on the older commit. The checklist below is historical planning context, not a statement that publication is still pending. Registry package publication is tracked separately; see the root README for the checked per-ecosystem status. The independent external audit remains open.

## Release identity

- Version: 4.1.1
- Git tag: v4.1.1
- Release tag commit: `5dd564daab9da1c071b8b134894ea7c4eba95d09`
- Current `main` baseline and mutable `v4.1.1` tag: updated together; the existing release assets and provenance still identify the older `5dd564daab9da1c071b8b134894ea7c4eba95d09` commit
- Release type: published stable-line release
- Public GitHub release: [v4.1.1](https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.1)

The original candidate and release-gate text below is retained as historical planning evidence. The published tag and current `main` are different source snapshots; use the exact tag when referring to the GitHub release and the separately linked CI run when referring to current `main`. The registry publication status is ecosystem-specific and is summarized in the root README.

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

## Original final acceptance contract (historical)

This was the pre-publication checklist; it is not a claim that publication is still pending. The release is already published:

1. Every NEXUS-Q workspace package and versioned SDK manifest resolves to 4.1.1; Cargo.lock is consistent with the workspace.
2. Formatting, locked checks, Clippy with -D warnings, debug tests and release
   tests pass.
3. C, Python, CLI and server smoke tests pass.
4. Ubuntu, macOS and Windows release builds pass.
5. The deployment archive is byte-for-byte reproducible when packaged twice
   from the same runner/build output.
6. SHA-256 checksums, a CycloneDX 1.5 SBOM and machine-readable provenance
   are emitted as release evidence.
7. Release provenance is published in `nexusq-v4.1.1-provenance.json` and identifies commit `5dd564d`. The mutable `v4.1.1` tag now follows `main`, while the bare `4.1.1` tag and existing release assets remain tied to the older commit. These references are not equivalent; do not assume the pre-existing assets/provenance match the updated `v4.1.1` tag.
8. The GitHub Release is created only after the complete gate is green.

## Original pre-tag requirements (historical)

1. The 4.1.1 branch review is complete and the branch is merged into `main`.
2. Required multi-hour fuzz soaks (vault parser, envelope parser) are executed and confirmed green on the exact merged SHA.
3. Post-merge `main` CI is green.
4. All release artifacts and native runtime checksums are generated and verified for 4.1.1.
5. The historical SwiftPM tag-collision concern was checked on 2026-10-23: the bare `4.1.1` tag remains on `5dd564d`, while the mutable `v4.1.1` tag has since been updated to follow `main`. Avoid assuming the tags or existing release assets identify the same source snapshot.
6. The owner explicitly authorizes tag push and publication; preparing this branch alone does not publish anything.

## Publication boundary

The GitHub release and language-registry packages are separate publication operations. Availability of a version in a registry does not by itself prove that the package was built from the same Git commit as the GitHub release tag. The root README records the checked endpoints and any known source-version distinctions.

## Security and audit status

- The native backend remains experimental and opt-in; this release does not
  enable it by default anywhere.
- No FIPS 140-3 validation and no pairwise consistency test (PCT) is claimed.
- The Phase 21 independent external audit remains open; this release is prepared
  so that audit can proceed against a stable, versioned line.

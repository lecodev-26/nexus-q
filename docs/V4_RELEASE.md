# NEXUS-Q Release Documentation — v4.1.2 Release and v4.1.1 History

> **Verified 2026-10-28:** NEXUS-Q v4.1.2 is the current published GitHub release. Public status: **“Audit-Ready Release. No production-readiness claim, no FIPS validation, external audit pending.”** Registry publication is tracked package by package; a source manifest at version 4.1.2 is not proof that every workspace crate has been published.

## v4.1.2 release evidence and closeout

- **GitHub Release:** [v4.1.2 — Audit-Ready Release](https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.2), published 2026-10-27; public, not draft, not prerelease.
- **Source identity:** annotated tag `v4.1.2` peels to commit `8735e5537bc687ee906ed68bdf119fc8956d9439`; this matches `HEAD`, the release manifest, and the provenance JSON in the published assets.
- **Release CI:** [workflow run 40598965703](https://github.com/lecodev-26/nexus-q/actions/runs/40598965703) completed successfully on the exact release commit. The stable-line gate, cross-platform release builds, SDK smoke, reproducible packaging, evidence upload, runtime builds, provenance/manifest generation, artifact attestation, and GitHub release publication jobs report success.
- **Declared MSRV:** root `Cargo.toml` declares Rust 1.88. The [MSRV CI pipeline run 40458251043](https://github.com/lecodev-26/nexus-q/actions/runs/40458251043) also completed successfully on the exact release commit.
- **Artifact integrity:** all 14 public GitHub Release assets matched GitHub's published SHA-256 digest and byte size. The 12 files listed in `release-manifest.json` also matched the manifest and `SHA256SUMS`; all 8 entries in `NATIVE-RUNTIME-SHA256SUMS` matched the manifest and release checksum file. `SHA256SUMS` covers 13 files, including the manifest; it does not checksum itself. The published CycloneDX SBOM contains 17 components.
- **Maven Central:** Java `io.github.lecodev-26:nexusq:4.1.2` and Kotlin `io.github.lecodev-26:nexusq-kotlin:4.1.2` have public POMs, JARs, sources JARs, Javadocs JARs and signature files returning HTTP 200. The Kotlin Maven command later timed out while polling Sonatype status after the bundle upload; the public artifacts are now present, so do not redeploy the same version.
- **Other verified registry versions:** crates.io `nexusq`, `nexusq-core`, `nexusq-kernels`, `nexusq-ml-kem`, `nexusq-ml-dsa`, `nexusq-c`, `nexusq-py`, `nexusq-cli`, and `nexusq-server` at `4.1.2`; `nexusq-native-backend` remains independently versioned at `0.1.0`. PyPI `nexusq==4.1.2` (sdist only), npm `nexusq@4.1.2`, NuGet `Nexusq/4.1.2`, pub.dev `nexusq 4.1.2`, RubyGems `nexusq 4.1.2`, and Packagist `lecodev-26/nexusq v4.1.2` were verified through their public version endpoints. The Go module is `v0.1.0`; its runtime pin `4.1.2` and every published runtime checksum were verified. The SwiftPM `v4.1.2` tag exists.
- **Explicit registry exceptions:** `nexusq-admin`, `nexusq-enrollment`, `nexusq-ha`, `nexusq-hsm`, `nexusq-ocsp`, `nexusq-tsa`, `nexusq-x509`, and `nexusq-pki-cluster` do not have a `4.1.2` version on crates.io (their exact version endpoints return HTTP 404). Treat these as source-only for v4.1.2; `nexusq-pki-cluster` has a historical `4.1.1` registry record. The installation matrix must not present these as installable `cargo add ...@4.1.2` packages.
- **Local Termux limitation:** the manual Java SDK test run in Termux failed because the Android environment could not load JNA's glibc-linked native dispatcher (`libc.so.6` missing). This is not a passing local test; it is also not evidence that the supported glibc Linux release CI failed—the tag-gated release workflow's SDK smoke job passed. The failure and environment limitation are retained in `STATE.md`.
- **Claims boundary:** this is an Audit-Ready Release only. No production-readiness claim, no FIPS 140-3 validation, no Common Criteria certification, and no completed independent external audit are claimed. Registry availability and checksums do not prove every package was built from the same Git commit.

## Historical record: v4.1.1

The sections below document the already-published v4.1.1 release and its known evidence limitations; they are not the v4.1.2 acceptance record.

The GitHub release is published at [`v4.1.1`](https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.1). The mutable `v4.1.1` tag now points to the current `main` commit, while the existing release provenance and previously published assets still identify commit `5dd564daab9da1c071b8b134894ea7c4eba95d09`; the bare `4.1.1` tag remains on the older commit. Treat the existing v4.1.1 provenance and assets as evidence incomplete for the current tag. Registry publication is ecosystem-specific; see the root README. The independent external audit remains open.

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

# NEXUS-Q v4.1.1 Stable Line Release

## Release identity

- Version: 4.1.1
- Git tag: v4.1.1
- Release branch: `main` (after the 4.1.1 development branch has passed review and is merged)
- Release type: proposed 4.1.1 candidate; not yet released
- Public GitHub release: not published; the release workflow remains a gated/manual operation

The v4.1.1 release candidate is prepared on `work/4.1.1-development`. A release may be produced from `main` only after branch CI is green, review is complete, and the required fuzz soaks have been executed and confirmed green on the exact merged SHA. This document describes the intended release contract, not evidence that those remote gates have already passed. The release gate re-runs correctness, security-sensitive
regression, build and packaging checks from the final version.

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

## Final acceptance contract

The release is eligible for publication only when:

1. Every NEXUS-Q workspace package and versioned SDK manifest resolves to 4.1.1; Cargo.lock is consistent with the workspace.
2. Formatting, locked checks, Clippy with -D warnings, debug tests and release
   tests pass.
3. C, Python, CLI and server smoke tests pass.
4. Ubuntu, macOS and Windows release builds pass.
5. The deployment archive is byte-for-byte reproducible when packaged twice
   from the same runner/build output.
6. SHA-256 checksums, a CycloneDX 1.5 SBOM and machine-readable provenance
   are emitted as release evidence.
7. The release tag path generates a GitHub build-provenance attestation for the release archive. **Tag blocker:** a remote bare `4.1.1` tag already exists for an earlier Swift Package Manager commit. Do not move or overwrite it. The owner must resolve the semantic-version/tag collision before cutting or pushing a new 4.1.1 release tag; a new `v4.1.1` tag alone may leave SwiftPM resolving the old `4.1.1` tag.
8. The GitHub Release is created only after the complete gate is green.

## Pre-tag requirements (before cutting v4.1.1)

1. The 4.1.1 branch review is complete and the branch is merged into `main`.
2. Required multi-hour fuzz soaks (vault parser, envelope parser) are executed and confirmed green on the exact merged SHA.
3. Post-merge `main` CI is green.
4. All release artifacts and native runtime checksums are generated and verified for 4.1.1.
5. Resolve the existing remote `4.1.1` SwiftPM tag collision without rewriting a published tag.
6. The owner explicitly authorizes tag push and publication; preparing this branch alone does not publish anything.

## Publication boundary

This phase publishes the GitHub source/tag/release artifact. It does not
automatically publish crates.io, PyPI or other SDK registries. Those registries
remain separate release operations with their own package metadata, credentials,
compatibility checks, provenance and publication gates.

## Security and audit status

- The native backend remains experimental and opt-in; this release does not
  enable it by default anywhere.
- No FIPS 140-3 validation and no pairwise consistency test (PCT) is claimed.
- The Phase 21 independent external audit remains open; this release is prepared
  so that audit can proceed against a stable, versioned line.

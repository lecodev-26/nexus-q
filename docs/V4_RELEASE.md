# NEXUS-Q v4.1.0 Stable Line Release

## Release identity

- Version: 4.1.0
- Git tag: v4.1.0
- Release branch: `main` (after PR [#55](https://github.com/lecodev-26/nexus-q/pull/55) is merged)
- Release type: stable line release of the V4 work, ready for the final independent audit
- Public GitHub release: published by the tag-gated `v4-release.yml` path after the full release gate passes

The v4.1.0 release is produced from `main` after the PR #55 review gates are
green and the two four-hour fuzz soaks have been executed and confirmed green
on the exact merged SHA. The release gate re-runs correctness, security-sensitive
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

1. Every NEXUS-Q workspace package resolves to 4.1.0.
2. Formatting, locked checks, Clippy with -D warnings, debug tests and release
   tests pass.
3. C, Python, CLI and server smoke tests pass.
4. Ubuntu, macOS and Windows release builds pass.
5. The deployment archive is byte-for-byte reproducible when packaged twice
   from the same runner/build output.
6. SHA-256 checksums, a CycloneDX 1.5 SBOM and machine-readable provenance
   are emitted as release evidence.
7. The public `v4.1.0` tag path generates a GitHub build-provenance attestation
   for the release archive.
8. The GitHub Release is created only after the complete gate is green.

## Pre-tag requirements (before cutting v4.1.0)

1. PR #55 merged into `main`.
2. The two four-hour fuzz soaks (vault parser, envelope parser) executed and
   confirmed green on the exact merged SHA.
3. Post-merge `main` CI green.

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

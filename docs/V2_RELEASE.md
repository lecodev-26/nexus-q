# NEXUS-Q v2.0.0 Final Release

## Release identity

- Version: 2.0.0
- Git tag: v2.0.0
- Release branch: nexusqv2
- Release type: final engineering release
- Public GitHub release: published by the protected `v2.0.0` tag path after final gates pass

The v2.0.0 release is produced from the merged nexusqv2 line after the V2-10
performance gate and V2-11 release-candidate gate. The final release gate
re-runs correctness, security-sensitive regression, build and packaging checks
from the final version. V2 is intentionally frozen without claiming a performance
win over V1; the retained Arena comparison is the baseline for V3.

## Final acceptance contract

The release is eligible for publication only when:

1. Every NEXUS-Q workspace package resolves to 2.0.0.
2. Cargo.lock is locked and contains no 2.0.0-rc.1 package entries.
3. Formatting, locked checks, Clippy with -D warnings, debug tests and release
   tests pass.
4. C, Python, CLI and server smoke tests pass.
5. Ubuntu, macOS and Windows release builds pass.
6. The deployment archive is byte-for-byte reproducible when packaged twice
   from the same runner/build output.
7. SHA-256 checksums, a CycloneDX 1.5 SBOM and machine-readable provenance
   are emitted as release evidence.
8. The public v2.0.0 tag path generates a GitHub build-provenance attestation
   for the release archive.
9. The GitHub Release is created only after the complete gate is green.

## Publication boundary

This phase publishes the GitHub source/tag/release artifact. It does not
automatically publish crates.io, PyPI or other SDK registries. Those registries
remain separate release operations with their own package metadata, credentials,
compatibility checks, provenance and publication gates.

A successful GitHub release therefore must not be interpreted as proof that
every downstream registry or commercial-readiness requirement is complete.

## Verification

Download the release archive and its checksum from the GitHub Release, then:

    sha256sum -c nexusq-v2.0.0-<TARGET>.tar.gz.sha256

After extraction:

    cd nexusq-v2.0.0-<TARGET>
    sha256sum -c SHA256SUMS

GitHub's artifact-attestation UI/API can be used to verify the build provenance
for the published archive.

## Security and evidence boundary

The release gate preserves the existing NEXUS-Q security model and does not
change cryptographic parameters, key-management semantics, zeroization policy,
audit-chain semantics or backend security boundaries.

An external security audit, formal certification, legal/compliance review,
commercial support/SLA, customer validation and package-registry publication
remain distinct claims and must not be inferred from the GitHub release alone.

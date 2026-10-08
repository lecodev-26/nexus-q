# NEXUS-Q v2.0 Release Candidate

## Candidate

The V2 release candidate is **2.0.0-rc.1**.

This phase freezes the engineering state for release validation. It does not
publish crates, PyPI packages, SDK registries, or a final GitHub release.

## V2-11 acceptance contract

The candidate is complete only when all of these are green on the exact
candidate commit:

1. All NEXUS-Q workspace packages are exactly `2.0.0-rc.1`, including the
   internal `nexusq-core` dependency and `Cargo.lock`.
2. Format, locked workspace check, Clippy with `-D warnings`, workspace
   tests, release-profile tests and release builds pass.
3. The deployment artifact is byte-for-byte reproducible when packaged twice
   from the same build.
4. SHA-256 checksums are generated for the release evidence.
5. A CycloneDX 1.5 SBOM is generated from locked Cargo metadata.
6. Machine-readable provenance records the exact Git commit and artifact
   checksums. RC provenance is explicitly unsigned.
7. Ubuntu, macOS and Windows release builds compile successfully.
8. C, Python, CLI and server package tests pass.
9. The RC acceptance contract is checked by CI itself.

## Evidence boundary

The RC gate does not prove an independent external security audit,
certification, signed public release provenance, production support/SLA,
package-registry publication, or commercial readiness.

## Publication boundary

V2-11 produces CI evidence only. Public publication is deferred to V2-12,
where the final version, signing, release artifacts and package registry gates
are evaluated again from the frozen candidate.


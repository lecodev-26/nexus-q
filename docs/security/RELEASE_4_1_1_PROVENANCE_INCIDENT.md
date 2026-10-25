# NEXUS-Q 4.1.1 historical provenance incident

**Status: contained; historical release classified as mixed-provenance.**  
**Evidence snapshot:** 2026-10-25.  
**Scope:** GitHub release assets and ecosystem packages published as `4.1.1`.
**Independent audit:** not completed. The audit scope is a draft in [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md); this incident review and local tests are not a substitute for an external audit.

## Finding

There is no evidence-supported single source commit that can honestly be assigned to every artifact published under version `4.1.1`. This is a historical integrity incident, not a missing checksum that can be repaired by regenerating a JSON file.

The strongest evidence for the GitHub release binaries is the verified GitHub SLSA build attestation: the main archive and eight runtime artifacts match its subject digests, and the attestation records source commit `5dd564daab9da1c071b8b134894ea7c4eba95d09` and workflow ref `refs/tags/v4.1.1`. But the current remote `v4.1.1` tag and `main` resolve to `84992f91589ae56957fdd5b2a727fcaef7f108a1`, while the annotated bare tag `4.1.1` resolves to `5dd564daab9da1c071b8b134894ea7c4eba95d09`.

SDK/package impact is being triaged separately in [`SDK_4_1_1_TRIAGE.md`](SDK_4_1_1_TRIAGE.md). The current evidence establishes source-identity gaps, not a confirmed malicious artifact. A byte-level comparison now shows the NuGet Windows DLL has the same `.text` bytes as the attested GitHub DLL; the whole-file hash difference is limited to 77 metadata/import-hint byte positions. Package-level NuGet provenance and the Rust source-revision split remain open follow-ups.

Independent package checks now distinguish reproducible contents from signed provenance. All 17 crates.io archives reproduce byte-for-byte from their recorded commits; the npm tar stream and PyPI sdist reproduce from `5dd564d…`; Maven source JARs reproduce from the same source family (binary Kotlin classes are identical, Java bytecode disassembly matches but two class files differ bytewise); and Packagist dist matches `b243950…`. pub.dev and RubyGems contents are consistent but do not identify a unique commit. NuGet declares `5b8a663…`; the managed assembly embeds that informational version and the README matches the source, while the Windows native DLL has the same executable `.text` bytes as the attested asset and only 77 metadata/import-hint byte differences. The NuGet `.signature.p7s` exists but was not verified here, and signed source/build provenance remains unresolved. See [`../RELEASE_INTEGRITY_INVENTORY.md`](../RELEASE_INTEGRITY_INVENTORY.md), [`SDK_4_1_1_TRIAGE.md`](SDK_4_1_1_TRIAGE.md), and [`CRATES_IO_4_1_1_INVENTORY.md`](CRATES_IO_4_1_1_INVENTORY.md) for details.

## Resolution decision

1. **Do not claim one canonical commit for all existing `4.1.1` artifacts.** For the nine GitHub-attested release/runtime files only, the verified build identity is `5dd564daab9da1c071b8b134894ea7c4eba95d09`.
2. **Preserve existing evidence.** Do not overwrite or delete published assets, regenerate attestations for old binaries, or silently retarget either historical tag. A new checksum or provenance JSON cannot repair the historical mismatch.
3. **Keep `4.1.1` publication blocked.** Release automation must reject the version while `4.1.1` and `v4.1.1` resolve to different commits. The local/manual publisher applies the same two-tag equality check as the GitHub release workflow.
4. **Use a new version for any replacement release.** Before publishing it, create and verify immutable matching version tags, choose the exact full source SHA, build from that SHA, generate checksums and a complete SBOM, verify signed provenance for every artifact, and record per-registry results. Never reuse `4.1.1` to imply the old package set has been repaired.
5. **Treat existing ecosystem packages individually.** Registry presence, registry `gitHead`, package contents, or a checksum do not substitute for a verified build attestation. Where no trustworthy source provenance exists, record it as unverified rather than inferring a commit.

## What this resolves—and what it does not

This closes the ambiguity in the release's security posture: `4.1.1` is formally designated a mixed-provenance release, its GitHub-attested subset has a known source identity, and future publication cannot proceed through the guarded paths while tag identity is inconsistent. Reproducible package contents have now been established for several ecosystems, but that is not the same as signed source/build provenance; other packages remain ambiguous or incompletely reproduced. It does **not** prove who or when moved the `v4.1.1` ref, establish one unique source commit for every package, validate the NuGet signature, or retroactively resolve all registry identities.

No tags, published release assets, registry packages, or cryptographic behavior are changed by this remediation.

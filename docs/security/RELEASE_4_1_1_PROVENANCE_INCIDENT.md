# NEXUS-Q 4.1.1 historical provenance incident

**Status: contained; historical release classified as mixed-provenance.**  
**Evidence snapshot:** 2026-10-25.  
**Scope:** GitHub release assets and ecosystem packages published as `4.1.1`.

## Finding

There is no evidence-supported single source commit that can honestly be assigned to every artifact published under version `4.1.1`. This is a historical integrity incident, not a missing checksum that can be repaired by regenerating a JSON file.

The strongest evidence for the GitHub release binaries is the verified GitHub SLSA build attestation: the main archive and eight runtime artifacts match its subject digests, and the attestation records source commit `5dd564daab9da1c071b8b134894ea7c4eba95d09` and workflow ref `refs/tags/v4.1.1`. But the current remote `v4.1.1` tag and `main` resolve to `84992f91589ae56957fdd5b2a727fcaef7f108a1`, while the annotated bare tag `4.1.1` resolves to `5dd564daab9da1c071b8b134894ea7c4eba95d09`.

SDK/package impact is being triaged separately in [`SDK_4_1_1_TRIAGE.md`](SDK_4_1_1_TRIAGE.md). The current evidence establishes source-identity gaps, not a confirmed malicious artifact; the NuGet Windows native library and the Rust source-revision split are the highest-priority technical follow-ups.

Independent package checks also find divergent source references: crates.io records four source commits across 17 packages; NuGet declares `5b8a663…` and its Windows native library differs from the attested GitHub asset; Packagist's downloaded dist exactly matches `b243950…`; and several other registries do not expose enough signed source evidence to identify a unique commit. See [`../RELEASE_INTEGRITY_INVENTORY.md`](../RELEASE_INTEGRITY_INVENTORY.md) and [`CRATES_IO_4_1_1_INVENTORY.md`](CRATES_IO_4_1_1_INVENTORY.md) for the detailed evidence and hashes.

## Resolution decision

1. **Do not claim one canonical commit for all existing `4.1.1` artifacts.** For the nine GitHub-attested release/runtime files only, the verified build identity is `5dd564daab9da1c071b8b134894ea7c4eba95d09`.
2. **Preserve existing evidence.** Do not overwrite or delete published assets, regenerate attestations for old binaries, or silently retarget either historical tag. A new checksum or provenance JSON cannot repair the historical mismatch.
3. **Keep `4.1.1` publication blocked.** Release automation must reject the version while `4.1.1` and `v4.1.1` resolve to different commits. The local/manual publisher applies the same two-tag equality check as the GitHub release workflow.
4. **Use a new version for any replacement release.** Before publishing it, create and verify immutable matching version tags, choose the exact full source SHA, build from that SHA, generate checksums and a complete SBOM, verify signed provenance for every artifact, and record per-registry results. Never reuse `4.1.1` to imply the old package set has been repaired.
5. **Treat existing ecosystem packages individually.** Registry presence, registry `gitHead`, package contents, or a checksum do not substitute for a verified build attestation. Where no trustworthy source provenance exists, record it as unverified rather than inferring a commit.

## What this resolves—and what it does not

This closes the ambiguity in the release's security posture: `4.1.1` is formally designated a mixed-provenance release, its GitHub-attested subset has a known source identity, and future publication cannot proceed through the guarded paths while tag identity is inconsistent. It does **not** retroactively make third-party registry packages reproducible, prove who or when moved the `v4.1.1` ref, or establish that every historical package was built from `5dd564d…`.

No tags, published release assets, registry packages, or cryptographic behavior are changed by this remediation.

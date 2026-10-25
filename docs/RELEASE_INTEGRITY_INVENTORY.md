# Release integrity inventory — 2026-10-25

## Purpose and boundary

This is a read-only inventory of the public `4.1.1` release identity, recorded to prevent a future workflow run from silently replacing evidence or combining assets from different source snapshots. It does **not** select the final source commit for `4.1.1`, declare the existing binaries invalid, or authorize republication. The release identity decision remains pending maintainer review.

No Git tag, published release asset, or registry package was changed while preparing this inventory.

## Observed Git refs

Queried from the remote `lecodev-26/nexus-q` repository on 2026-10-25:

| Ref | Remote object | Resolved commit | Meaning |
|---|---|---|---|
| `4.1.1` | annotated tag object `78341ecff5b0ad04b43e77c1cc3b54628b9d7787` | `5dd564daab9da1c071b8b134894ea7c4eba95d09` | Historical release snapshot; tag message `NexusQ 4.1.1` |
| `v4.1.1` | lightweight tag object / commit `84992f91589ae56957fdd5b2a727fcaef7f108a1` | `84992f91589ae56957fdd5b2a727fcaef7f108a1` | Same commit as remote `main` at inventory time |
| `main` | branch ref | `84992f91589ae56957fdd5b2a727fcaef7f108a1` | Current engineering baseline at inventory time |

These two version tags are not interchangeable. The bare tag `4.1.1` and `v4.1.1` resolve to different commits. A later movement of either ref would change its resolution and must be recorded as an identity event, not treated as proof that existing binaries were rebuilt.

## Published GitHub release evidence

Public release: <https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.1>

The release is published (not a draft or prerelease), with assets uploaded on 2026-10-22. The inventory retrieved these assets from the release:

- `nexusq-v4.1.1-provenance.json`
- `nexusq-v4.1.1-sbom.cdx.json`
- `SHA256SUMS`
- `NATIVE-RUNTIME-SHA256SUMS`
- Main release archive `nexusq-v4.1.1-x86_64-unknown-linux-gnu.tar.gz`
- Platform archives and native runtime libraries for Linux, macOS, and Windows

The published provenance states:

- release: `4.1.1`
- commit: `5dd564daab9da1c071b8b134894ea7c4eba95d09`
- ref: `refs/tags/v4.1.1`
- workflow: `NEXUS-Q v4.1.1 Stable Line Release`
- external independent audit: pending

That declared build commit matches the target of the bare `4.1.1` tag, but not the current target of `v4.1.1` or `main`. The checksum file `SHA256SUMS` covers the main `.tar.gz` archive; native runtime assets have a separate checksum file. The CycloneDX 1.5 SBOM identifies `nexusq` 4.1.1 and contains 17 components, generated from workspace packages whose names start with `nexusq`; it is not a complete third-party dependency SBOM.

Asset checksums exposed by the GitHub release API identify the currently downloaded release files, but checksums alone do not establish which source commit produced them. The workflow's provenance field is a statement made by the workflow; it should be paired with verifiable build provenance/attestation and exact artifact digests.

## Release workflow risks found

File: [`.github/workflows/v4-release.yml`](../.github/workflows/v4-release.yml)

1. The workflow is manually dispatched and its public-release job previously allowed a run from `main` to update the public release.
2. Existing assets were uploaded with `gh release upload --clobber`, allowing the workflow to overwrite assets without resolving the historical source identity first.
3. At inventory time, the workflow used Rust `1.85.1` while the workspace declared `rust-version = "1.88"`. This PR aligns both release-workflow toolchain pins with Rust `1.88`; CI must verify the toolchain change before merge.
4. The generated SBOM filters to workspace packages with names beginning `nexusq`; third-party dependencies are not included by that filter.
5. The provenance file's checksum list is based on `SHA256SUMS`, which only lists the main release archive; native runtime checksums are generated separately.
6. The repository ruleset query returned no rulesets, and the tag-protection API did not expose a configured protection rule. This API result is not a complete audit of all organization-level controls; tag immutability/protection still needs maintainer verification.

This PR makes publication opt-in, requires both the explicit `confirm_release_identity` workflow input and the repository variable `NEXUSQ_RELEASE_IDENTITY_APPROVED=true`, requires the exact release tag to match the checked-out commit, and refuses to mutate an already existing `v4.1.1` release. The repository variable is intentionally not configured by this PR. It must remain unset until a maintainer has resolved the identity decision and reviewed the evidence. This PR does not retarget refs or decide which source snapshot should ultimately represent the version.

## Required decision before any release recovery

- [ ] Maintainer explicitly selects the source commit that `4.1.1` is intended to represent.
- [ ] Record the historical `5dd564d…` artifacts and their evidence without overwriting them.
- [ ] Reconcile the chosen commit with both tags and the release's immutable provenance/attestations.
- [ ] Determine which registry packages were built from which source snapshot; registry availability is not provenance.
- [ ] Rebuild only after the selected source identity and toolchain policy are approved.
- [ ] Generate checksums for every published artifact, and verify each checksum against the downloaded asset set.
- [ ] Generate a dependency-complete SBOM, including third-party dependencies and package metadata.
- [ ] Generate and verify provenance/attestations against the exact tag, commit, workflow run, and artifact digests.
- [ ] Publish through a separately reviewed procedure; do not overwrite or merge old and new artifacts under the same version without an explicit, documented decision.

## Out of scope for this PR

This inventory does not change cryptographic implementation, resolve `RUSTSEC-2023-0071`, change SDK/package versions, publish packages, move tags, delete release assets, or claim an external audit, FIPS validation, certification, or production readiness.

## Cross-registry package identity evidence

Read-only metadata checks were performed on 2026-10-25. These results identify what each registry exposes; a registry's source reference or archive digest is not, by itself, a verified build attestation.

| Ecosystem / package | Published version | Registry metadata evidence | Identity conclusion |
|---|---|---|---|
| npm `nexusq` | `4.1.1` | npm metadata `gitHead=5dd564daab9da1c071b8b134894ea7c4eba95d09`; package integrity is published by npm | Source reference agrees with the release provenance and bare `4.1.1` tag, but disagrees with current `v4.1.1` / `main`. |
| NuGet `Nexusq` | `4.1.1` | Published `.nuspec` repository metadata records commit `5b8a663b72d0d048d9f564d5650b13acdd0b8c0d` | Different source commit from both the release provenance and current `v4.1.1` tag. Requires investigation before claiming a unified release baseline. |
| Packagist `lecodev-26/nexusq` | `4.1.1` | Composer metadata source/dist reference `b243950cfbbd3e462e3b387d3ed65255b81ca64e`; metadata timestamp `2026-10-19T11:31:37Z` | Older, distinct source snapshot; not aligned to the two release commits listed above. |
| PyPI `nexusq` | `4.1.1` | Published sdist `nexusq-4.1.1.tar.gz`; SHA-256 `03b8f0d43555aaccc8d10b1d7182bf268a007ad5b235f8e4836c33f818fc800d`; upload time `2026-10-22T01:34:32` | Metadata checked does not expose a source commit. The sdist digest is recorded, but source identity remains unverified. |
| pub.dev `nexusq` | `4.1.1` | Archive SHA-256 `8f66fc7c168f0f4403ac12781eb3a00fb4eb0932f4f55b8111dc1cf77e022af0`; published `2026-10-22T02:00:12Z` | Metadata checked does not expose a source commit. Archive digest recorded; source identity remains unverified. |
| RubyGems `nexusq` | `4.1.1` | Registry reports gem SHA `f95d9b0efd863ffec18bc49256e39fd32b7dfa92ad0ebe9ed98b953735ed0be3`; created `2026-10-22T01:35:21Z` | Metadata checked does not expose a source commit or source-code URL. Source identity remains unverified. |
| crates.io `nexusq` and workspace crates | `4.1.1` declared in repository manifests | Direct crates.io API request was denied with HTTP 403 in this inventory environment | Registry-side version, checksum and publication metadata could not be independently confirmed by this request. Do not treat repository manifests as proof of registry contents. |
| Maven Central `io.github.lecodev-26:nexusq` and `io.github.lecodev-26:nexusq-kotlin` | `4.1.1` declared in repository POMs and installation docs | Maven Central search API returned zero results for group `io.github.lecodev-26` during this check | Publication and artifact digests were not independently confirmed by this query; verify exact coordinates/indexing before treating the docs as registry evidence. |

The npm, NuGet, and Packagist metadata therefore point to **three distinct source snapshots** across published 4.1.1 channels (`5dd564d…`, `5b8a663…`, and `b243950…`). The registry package publication state must be reconciled package-by-package; the version string alone is not a release identity.

## Downloaded asset checksum verification

All 13 assets attached to the GitHub `v4.1.1` release were downloaded to a separate review directory without uploading or modifying anything. Both published checksum manifests verified successfully:

- `SHA256SUMS`: main Linux release archive — **PASS**.
- `NATIVE-RUNTIME-SHA256SUMS`: all eight platform runtime archives/libraries — **PASS**.

This confirms the downloaded binary/runtime files match the published checksum manifests. It does **not** establish which commit built those files, validate the truth of the provenance JSON, or authenticate the checksum files independently. The provenance JSON itself is not covered by either checksum manifest, and the release's current `v4.1.1` ref still disagrees with its declared commit.

### Next evidence required

- [ ] Obtain the publication workflow logs and attestations for each package channel where available.
- [ ] Compare the source files inside PyPI, pub.dev, and RubyGems artifacts against candidate commits; record the exact method and result.
- [ ] Query crates.io through an available registry endpoint/tool and record per-crate checksums, upload timestamps, and any source/repository metadata.
- [ ] Verify Maven Central and other SDK package coordinates against their repository commit metadata and artifact digests.
- [ ] Do not infer that every package with version `4.1.1` was built from the same commit; keep each channel's evidence separate until proven otherwise.

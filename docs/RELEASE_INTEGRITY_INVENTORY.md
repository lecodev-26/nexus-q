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

That declared build commit matches the target of the bare `4.1.1` tag, but not the current target of `v4.1.1` or `main`. The checksum file `SHA256SUMS` covers the main `.tar.gz` archive; native runtime assets have a separate checksum file. The currently published CycloneDX 1.5 SBOM identifies `nexusq` 4.1.1 and contains 17 internal components with zero dependency relationships; it is not a complete third-party dependency SBOM. A lockfile-based generator has now been added for a future approved run, but no published asset was changed.

Asset checksums exposed by the GitHub release API identify the currently downloaded release files, but checksums alone do not establish which source commit produced them. The verified GitHub SLSA attestation for the main archive and eight runtime artifacts is documented below; it links those artifacts to commit `5dd564d…`, while the current `v4.1.1` tag points elsewhere.

## Release workflow risks found

File: [`.github/workflows/v4-release.yml`](../.github/workflows/v4-release.yml)

1. The workflow is manually dispatched and its public-release job previously allowed a run from `main` to update the public release.
2. Existing assets were uploaded with `gh release upload --clobber`, allowing the workflow to overwrite assets without resolving the historical source identity first.
3. At inventory time, the workflow used Rust `1.85.1` while the workspace declared `rust-version = "1.88"`. This PR aligns both release-workflow toolchain pins with Rust `1.88`; CI must verify the toolchain change before merge.
4. The currently published SBOM filters to workspace packages with names beginning `nexusq` and has zero dependency relationships. This PR replaces the workflow generator with `.github/scripts/generate_cargo_sbom.py`, which reads `Cargo.lock`, records hashes for registry packages, and emits dependency relationships. A local generation from the current lockfile produced 359 package nodes and 1,048 dependency edges (341 non-`nexusq` components). The published asset is not being overwritten; the new generator applies only to a separately approved workflow run/recovery procedure.
5. The provenance file's checksum list is based on `SHA256SUMS`, which only lists the main release archive; native runtime checksums are generated separately.
6. The repository ruleset query returned no rulesets, and the tag-protection API did not expose a configured protection rule. This API result is not a complete audit of all organization-level controls; tag immutability/protection still needs maintainer verification.

This PR makes publication opt-in, requires both the explicit `confirm_release_identity` workflow input and the repository variable `NEXUSQ_RELEASE_IDENTITY_APPROVED=true`, requires the exact release tag to match the checked-out commit, and refuses to mutate an already existing `v4.1.1` release. The repository variable is intentionally not configured by this PR. It must remain unset until a maintainer has resolved the identity decision and reviewed the evidence. This PR does not retarget refs or decide which source snapshot should ultimately represent the version. The manual publisher now also fails closed through `.github/scripts/verify_release_identity.py`: it requires an explicit `NEXUSQ_RELEASE_IDENTITY_APPROVED=true`, a full `NEXUSQ_APPROVED_RELEASE_COMMIT` SHA, a clean worktree, the official repository remote, and exact equality between `HEAD`, the approved SHA, and `vVERSION`. The crate-publishing helper runs the same gate directly, so invoking it without the wrapper cannot bypass the check. No registry publishing was performed.

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

## Cross-ecosystem package identity evidence

Read-only metadata checks were performed on 2026-10-25. These results identify what each registry exposes; a registry's source reference or archive digest is not, by itself, a verified build attestation.

| Ecosystem / package | Published version | Registry metadata evidence | Identity conclusion |
|---|---|---|---|
| npm `nexusq` | `4.1.1` | npm metadata `gitHead=5dd564daab9da1c071b8b134894ea7c4eba95d09`; downloaded tarball SHA-256 `059cd1f65cea1c80fcbb045feca4b441c49d6e39ea6ea2210170724c83df74ff` | Registry source reference agrees with the release provenance and bare `4.1.1` tag, but disagrees with current `v4.1.1` / `main`. Package `package.json` and README bytes are identical at all three candidate commits checked, so the tarball contents do not independently prove `gitHead`. |
| NuGet `Nexusq` | `4.1.1` | Downloaded `.nupkg` SHA-256 `3254fa2488a61e31f0d177f45b42e02e01700374e924c2e3d25de98d56853b63`; `.nuspec` records commit `5b8a663b72d0d048d9f564d5650b13acdd0b8c0d` | Three native assets (Linux x64, Linux ARM64, macOS ARM64) are byte-identical to assets in the GitHub-attested release; the Windows DLL differs. The package itself has no verified NuGet build attestation in this inventory. Its declared commit and mixed native-artifact results need reconciliation. |
| Packagist `lecodev-26/nexusq` | `4.1.1` | Composer source/dist reference `b243950cfbbd3e462e3b387d3ed65255b81ca64e`; downloaded GitHub dist ZIP SHA-256 `6a2e1db0357e0af4c0d11235528c1af836fa9f5f9d3d69492003e8de58f8447e`; all 1,066 files matched that commit byte-for-byte | Strongly identifies the Packagist dist snapshot as `b243950…`; it is distinct from the release-attested commit and current `v4.1.1` tag. |
| PyPI `nexusq` | `4.1.1` | Sdist SHA-256 `03b8f0d43555aaccc8d10b1d7182bf268a007ad5b235f8e4836c33f818fc800d`; upload time `2026-10-22T01:34:32Z` | Of 393 compared files, 389 match both commits `5dd564d…` and `c0899e4…`; three generated/normalized metadata files differ and one generated `pyproject.toml` is not in the repository tree. Upload time predates `c0899e4`'s commit timestamp, which is consistent with `5dd564d…`, but the sdist has no cryptographically verified source commit. |
| pub.dev `nexusq` | `4.1.1` | Archive SHA-256 `8f66fc7c168f0f4403ac12781eb3a00fb4eb0932f4f55b8111dc1cf77e022af0`; published `2026-10-22T02:00:12Z` | All 10 archived files match the repository at `5dd564d…`, `5b8a663…`, and `84992f9…`; those files do not distinguish the source commit. |
| RubyGems `nexusq` | `4.1.1` | Gem SHA-256 `f95d9b0efd863ffec18bc49256e39fd32b7dfa92ad0ebe9ed98b953735ed0be3`; created `2026-10-22T01:35:21Z` | All three gem files match `5dd564d…`, `5b8a663…`, and `84992f9…`; package contents do not distinguish the source commit and registry metadata exposes no source revision. |
| crates.io `nexusq` and 16 workspace crates | `4.1.1` | Public sparse-index metadata was read for all 17 crates; all 17 downloaded `.crate` SHA-256 values matched the sparse-index checksums. Embedded `.cargo_vcs_info.json` records four source commits: `5dd564d…` (9 crates), `c0899e4…` (6), `3f8dfb7…` (1), and `38701d5…` (1). | Registry artifacts are confirmed and checksums match index metadata, but the published version is split across four recorded source snapshots. The 17-crate checksum/commit/MSRV matrix is in [`docs/security/CRATES_IO_4_1_1_INVENTORY.md`](security/CRATES_IO_4_1_1_INVENTORY.md). |
| Maven Central `io.github.lecodev-26:nexusq` | `4.1.1` | Direct Maven Central files confirmed. POM SHA-256 `e613b0f46fc5d79ff16b161500b4420d46c3efa37e89b5ccf68fcf6bbcf1ede0`; JAR SHA-256 `6074074d097620233ce27fcd470c07858bc3dc1fa839bbd700c66aad984cb593`; sources JAR SHA-256 `2bac8a5bf1074ce73c95947c8fe9751e3c23dc1989fe854a854f5984a6669707` | Published. POM has repository URL but no SCM commit/tag; sampled source files are identical across `5dd564d…`, `5b8a663…`, and `84992f9…`, so they do not identify a source snapshot. |
| Maven Central `io.github.lecodev-26:nexusq-kotlin` | `4.1.1` | Direct Maven Central files confirmed. POM SHA-256 `f511315f658ffd5f58bdbd318205b0666785c1ebe1f4019efe173d6922bd29a2`; JAR SHA-256 `3143e45faf1fe03cf29abc40cf36c9afe04366d2a9615fd18aff99d7a291b3c1`; sources JAR SHA-256 `ed5e78a21c2c00d10c1d02b00dd445027e90357ab9826c69c3d0a3962899f423` | Published. POM has repository URL but no SCM commit/tag; sampled Kotlin sources are identical across `5dd564d…`, `5b8a663…`, and `84992f9…`, so they do not identify a source snapshot. |
| Swift Package Manager | Repository tag `4.1.1` | Root `Package.swift` and installation docs use the bare semantic-version tag; that tag resolves to `5dd564daab9da1c071b8b134894ea7c4eba95d09` | SwiftPM users selecting `from: "4.1.1"` resolve the bare tag, not `v4.1.1`; the source snapshot is the attested historical commit and differs from current `main`. |
| Go nested module | Separate module version (project docs identify `v0.1.0`) | `bindings/go/nexusq/go.mod` is a nested module; the parent Go module uses a local `replace` and a development `v0.0.0` requirement | Not a `4.1.1` package channel. Verify its nested-module tag/version separately; do not imply it is covered by the 4.1.1 release identity. |

The manual publishing path was another integrity risk: `publicar.sh` previously relied on the existence of a GitHub release and then published from the current working tree, without verifying a clean tree, tag/HEAD equality, or a maintainer-approved commit. It now fails closed unless the local approval variables and repository approval variable are set, the working tree is clean, and `HEAD`, `vVERSION`, and the approved full SHA agree. The crates.io helper now covers all 17 workspace crates in dependency order plus the separate `nexusq-native-backend` package; registry status checks treat only HTTP 404 as absence and fail closed on other errors. NuGet publication is now manual-dispatch-only from the matching tag, with the same explicit confirmation and full commit SHA gate. These safeguards do not resolve the historical identity mismatch or authorize publication.

The npm, NuGet, and Packagist **registry metadata references** therefore point to three distinct source commits across published 4.1.1 channels (`5dd564d…`, `5b8a663…`, and `b243950…`). This is not proof that each package payload was faithfully built from its declared commit. The version string alone is not a release identity. The crates.io inventory independently confirms four source revisions embedded across 17 published Rust crate archives. These separate observations strengthen the conclusion that 4.1.1 currently names multiple source snapshots across package channels.

## Downloaded asset checksum verification

All 12 assets attached to the GitHub `v4.1.1` release were downloaded to a separate review directory without uploading or modifying anything. Both published checksum manifests verified successfully:

- `SHA256SUMS`: main Linux release archive — **PASS**.
- `NATIVE-RUNTIME-SHA256SUMS`: all eight platform runtime archives/libraries — **PASS**.

This confirms the downloaded binary/runtime files match the published checksum manifests. It does **not** establish which commit built those files, validate the truth of the provenance JSON, or authenticate the checksum files independently. The provenance JSON itself is not covered by either checksum manifest, and the release's current `v4.1.1` ref still disagrees with its declared commit.

## GitHub SLSA build attestation verification

The GitHub CLI `gh attestation verify` succeeded for the downloaded main release archive, scoped to repository `lecodev-26/nexus-q`. The verified in-toto/SLSA provenance records:

- Workflow identity: `.github/workflows/v4-release.yml` at `refs/tags/v4.1.1`.
- Source commit and workflow SHA: `5dd564daab9da1c071b8b134894ea7c4eba95d09`.
- Trigger: `workflow_dispatch`.
- Invocation: [GitHub Actions run 39704262006](https://github.com/lecodev-26/nexus-q/actions/runs/39704262006).
- Transparency-log verification timestamp: `2026-10-22T01:26:48Z`.
- The attestation's subject list contains nine release/runtime artifacts. Every one of those nine downloaded files matched the SHA-256 digest in the verified attestation.

**What this establishes:** the nine named files are cryptographically linked by a verified GitHub build attestation to the release workflow running against source commit `5dd564d…`. This is stronger evidence than the unsigned project-specific provenance JSON or the checksum manifests alone.

**What remains unresolved:** the current remote lightweight tag `v4.1.1` resolves to `84992f91589ae56957fdd5b2a727fcaef7f108a1`, not `5dd564d…`. The attestation establishes the historical build identity, not why or when the present tag diverged, nor whether all ecosystem packages were built from that same commit. Do not silently move the tag to make it agree. Preserve this attestation and tag evidence for the release-identity decision.

## Package archive spot checks

Read-only package downloads and content checks were performed on 2026-10-25. Hashes below identify the exact downloaded archives in this review; they are not independently signed attestations.

- **npm:** tarball SHA-256 `059cd1f65cea1c80fcbb045feca4b441c49d6e39ea6ea2210170724c83df74ff`; registry `gitHead` is `5dd564d…`. The inspected `package.json` and README are byte-identical at `5dd564d`, `5b8a663`, and `84992f9`; those files cannot independently corroborate the claimed source commit.
- **NuGet:** `.nupkg` SHA-256 `3254fa2488a61e31f0d177f45b42e02e01700374e924c2e3d25de98d56853b63`; embedded `.nuspec` declares commit `5b8a663…`. The Linux x64, Linux ARM64, and macOS ARM64 native libraries match three attested GitHub release assets exactly; the Windows DLL SHA-256 `0e35010fd2f4b3a83bd8342254cd97a39651c16298cf9db538b69972c48827e3` differs from the attested release DLL (`8eb55f8…`).
- **PyPI:** downloaded sdist SHA-256 matches the registry's reported digest (`03b8f0d43555aaccc8d10b1d7182bf268a007ad5b235f8e4836c33f818fc800d`). Of 393 compared files, 389 are byte-identical at both `5dd564d…` and `c0899e4…`; three normalized/generated metadata files differ and one generated `pyproject.toml` is not in the repository tree. The upload timestamp predates the `c0899e4` commit timestamp, which favors `5dd564d…` as the likely snapshot but is not a cryptographic attestation.
- **pub.dev:** downloaded archive SHA-256 matches registry metadata (`8f66fc7c168f0f4403ac12781eb3a00fb4eb0932f4f55b8111dc1cf77e022af0`). All 10 archived files match the repository at `5dd564d`, `5b8a663`, and `84992f9`; this package content does not identify one of those commits.
- **RubyGems:** downloaded gem SHA-256 matches the registry-reported SHA (`f95d9b0efd863ffec18bc49256e39fd32b7dfa92ad0ebe9ed98b953735ed0be3`). All three archived files match `5dd564d`, `5b8a663`, and `84992f9`; no source commit is established by this comparison.

- **Packagist:** downloaded GitHub dist ZIP SHA-256 `6a2e1db0357e0af4c0d11235528c1af836fa9f5f9d3d69492003e8de58f8447e`; all 1,066 archived files match commit `b243950…` byte-for-byte.
- **Maven Central:** both `nexusq:4.1.1` and `nexusq-kotlin:4.1.1` are published. POM/JAR/source-JAR digests are recorded in the registry matrix above. The POMs do not record a source commit; the sampled Java/Kotlin source files match multiple candidate commits and therefore do not prove source identity.

These spot checks show why matching checksums and a package version are necessary but insufficient for provenance. Keep registry metadata claims separate from independently verified source identity.

### Next evidence required

- [ ] Obtain the publication workflow logs and attestations for each package channel where available.
- [x] Compare source files inside PyPI, pub.dev, RubyGems, and Packagist artifacts against candidate commits; results and limitations are recorded above.
- [ ] Obtain a package-level signed provenance/attestation for NuGet or document that none is available, and reconcile its Windows native DLL with the GitHub release asset.
- [x] Query crates.io sparse-index metadata and record all 17 published crate checksums, source metadata and MSRV: [`docs/security/CRATES_IO_4_1_1_INVENTORY.md`](security/CRATES_IO_4_1_1_INVENTORY.md).
- [x] Verify Maven Central Java/Kotlin artifact coordinates and record POM/JAR/source-JAR digests; source commit remains unproven because POM metadata lacks an SCM revision and source files match multiple candidates.
- [ ] Reconcile the SwiftPM bare `4.1.1` tag with the `v4.1.1` release tag, and separately document the nested Go module version/tag.
- [ ] Do not infer that every package with version `4.1.1` was built from the same commit; keep each channel's evidence separate until proven otherwise.

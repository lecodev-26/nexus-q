# Release integrity inventory — 2026-10-25

## Purpose and boundary

This is a read-only inventory of the public `4.1.1` release identity, recorded to prevent a future workflow run from silently replacing evidence or combining assets from different source snapshots. It does **not** select the final source commit for `4.1.1`, declare the existing binaries invalid, or authorize republication. The release identity decision remains pending maintainer review.

**Incident disposition:** [`docs/security/RELEASE_4_1_1_PROVENANCE_INCIDENT.md`](security/RELEASE_4_1_1_PROVENANCE_INCIDENT.md) records the historical release as mixed-provenance, identifies the attested GitHub artifact subset, and defines containment. This is not a claim that all registry artifacts can be retroactively unified.

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

The GitHub Releases API check on 2026-10-25 reports release ID `420215670`, `draft=false`, `prerelease=false`, `immutable=false`, and 13 assets. A separate active repository ruleset now blocks updates/deletion of the `v4.1.1` tag (ruleset ID `25819747`); this does not freeze the release asset collection. `immutable=false` means GitHub does not mark this release as immutable; it is not evidence that an asset was actually changed. The release workflow in this PR refuses to overwrite an existing release, but that workflow guard does not retroactively make the existing GitHub release immutable. Asset digests and upload timestamps were also retrieved from the API; no release settings or assets were changed.

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

That declared build commit matches the target of the bare `4.1.1` tag, but not the current target of `v4.1.1` or `main`. The checksum file `SHA256SUMS` covers the main `.tar.gz` archive; native runtime assets have a separate checksum file. The currently published CycloneDX 1.5 SBOM identifies `nexusq` 4.1.1 and contains 17 internal components with zero dependency relationships; it is not a complete third-party dependency SBOM. The new generator was run locally against the exact `5dd564d…` `Cargo.lock` and `Cargo.toml`: lock SHA-256 `06420e8b9bbc4cb99838406d04dd858e7e652a15c0dea717b334d567ae4fc717`, 359 total package nodes, 358 components, 359 dependency nodes and 1,048 dependency edges. Of the components, 341 third-party registry packages carry lockfile checksums and 17 internal workspace packages are path/local entries without registry checksums. The generated metadata records commit `5dd564d…`, ref `refs/tags/v4.1.1`, and the exact lock hash. The current branch lockfile is different (`ae128359…`), so an SBOM made from that lock must not be labeled as the `5dd564d…` SBOM. No published asset was changed.

Asset checksums exposed by the GitHub release API identify the currently downloaded release files, but checksums alone do not establish which source commit produced them. The verified GitHub SLSA attestation for the main archive and eight runtime artifacts is documented below; it links those artifacts to commit `5dd564d…`, while the current `v4.1.1` tag points elsewhere.

## Release workflow risks found

File: [`.github/workflows/v4-release.yml`](../.github/workflows/v4-release.yml)

1. The workflow is manually dispatched and its public-release job previously allowed a run from `main` to update the public release.
2. Existing assets were uploaded with `gh release upload --clobber`, allowing the workflow to overwrite assets without resolving the historical source identity first.
3. At inventory time, the workflow used Rust `1.85.1` while the workspace declared `rust-version = "1.88"`. The current PR branch pins both release build jobs to Rust `1.88`, matching the current workspace. The PR fast workflow uses floating `stable`, not an explicit minimum-version matrix. Local tests in this review used Rust/Cargo `1.99.1`; neither the Rust 1.88 workspace MSRV nor the Rust 1.85 MSRV of the historical release snapshot was directly tested here. The registry reports 16 published crates with `rust_version = 1.85` and `nexusq-pki-cluster` at `1.88`; do not infer those minimums solely from the release build toolchain.
4. The currently published SBOM filters to workspace packages with names beginning `nexusq` and has zero dependency relationships. This PR replaces the workflow generator with `.github/scripts/generate_cargo_sbom.py`, which reads `Cargo.lock`, records hashes for registry packages, and emits dependency relationships. A local generation from the exact `5dd564d…` lockfile produced 359 package nodes and 1,048 dependency edges (341 third-party components with checksums). The current branch lockfile hash is `ae128359…`, different from the `5dd564d…` lock hash `06420e8b…`; commit/ref/lock metadata must be generated from the same source snapshot. The published asset is not being overwritten; the new generator applies only to a separately approved workflow run/recovery procedure.
5. The provenance file's checksum list is based on `SHA256SUMS`, which only lists the main release archive; native runtime checksums are generated separately.
6. At the initial inventory, the repository had no rulesets. On 2026-10-25, repository ruleset ID `25819747` (`Protect published v4.1.1 tag`) was created and verified active for `refs/tags/v4.1.1`, with `update` and `deletion` blocked and no bypass actors. The remote tag still resolves to `84992f91589ae56957fdd5b2a727fcaef7f108a1`; it was not moved. This protects the Git ref from update/deletion, but does not make the existing GitHub Release immutable: release ID `420215670` still reports `immutable=false`.

This PR makes publication opt-in, requires the explicit `confirm_release_identity` workflow input, the repository variable `NEXUSQ_RELEASE_IDENTITY_APPROVED=true`, and a full `approved_release_commit` SHA that matches both the selected `v4.1.1` tag and checked-out commit. It also refuses to mutate an already existing `v4.1.1` release. The repository variable is intentionally not configured by this PR. It must remain unset until a maintainer has resolved the identity decision and reviewed the evidence. This PR does not retarget refs or decide which source snapshot should ultimately represent the version. The manual publisher now also fails closed through `.github/scripts/verify_release_identity.py`: it requires an explicit `NEXUSQ_RELEASE_IDENTITY_APPROVED=true`, a full `NEXUSQ_APPROVED_RELEASE_COMMIT` SHA, a clean worktree, the official repository remote, and exact equality between `HEAD`, the approved SHA, `VERSION`, and `vVERSION`. The two version tags must resolve to the same commit; this prevents an approval for one spelling from concealing the other tag's divergent history. The crate-publishing helper runs the same gate directly, so invoking it without the wrapper cannot bypass the check. No registry publishing was performed.

## Required decision before any release recovery

- [x] Classify the historical incident: there is no defensible single source commit for every artifact published as `4.1.1`; the GitHub-attested release assets are tied to `5dd564daab9da1c071b8b134894ea7c4eba95d09`, while other package channels expose multiple other source revisions.
- [ ] Maintainer explicitly selects the source commit for any future, newly versioned release. Do not reinterpret that choice as proof that all existing `4.1.1` packages share the same source.
- [ ] Record the historical `5dd564d…` artifacts and their evidence without overwriting them.
- [x] Preserve the original tag and attestation observations; the current `4.1.1` and `v4.1.1` refs are divergent and are not silently rewritten by this remediation.
- [ ] For any future release, create a new version with fresh immutable tags and verify every package channel independently against that release identity.
- [ ] Determine which registry packages were built from which source snapshot; registry availability is not provenance.
- [ ] Rebuild only after the selected source identity and toolchain policy are approved.
- [ ] Generate checksums for every published artifact, and verify each checksum against the downloaded asset set.
- [ ] Generate a dependency-complete SBOM, including third-party dependencies and package metadata.
- [ ] Generate and verify provenance/attestations against the exact tag, commit, workflow run, and artifact digests.
- [ ] Publish through a separately reviewed procedure; do not overwrite or merge old and new artifacts under the same version without an explicit, documented decision.

## Out of scope for this PR

This inventory does not change cryptographic implementation, resolve `RUSTSEC-2023-0071`, change SDK/package versions, publish packages, move tags, delete release assets, or claim an external audit, FIPS validation, certification, or production readiness. The incident is resolved operationally as a **mixed-provenance release**, not by pretending the old version can be retroactively made uniform: existing `4.1.1` artifacts and evidence are preserved, all `4.1.1` publication paths remain blocked while the two Git tags diverge, and any replacement must use a new version and independently verifiable provenance.

SDK/package impact triage and remediation order are tracked in [`docs/security/SDK_4_1_1_TRIAGE.md`](security/SDK_4_1_1_TRIAGE.md). It distinguishes confirmed provenance gaps from unproven code compromise and prioritizes NuGet package-level verification; the Windows DLL difference is now narrowed to non-`.text` metadata/import-hint bytes.

## Cross-ecosystem package identity evidence

Read-only metadata checks were performed on 2026-10-25. These results identify what each registry exposes; a registry's source reference or archive digest is not, by itself, a verified build attestation.

| Ecosystem / package | Published version | Registry metadata evidence | Identity conclusion |
|---|---|---|---|
| npm `nexusq` | `4.1.1` | npm metadata `gitHead=5dd564daab9da1c071b8b134894ea7c4eba95d09`; downloaded tarball SHA-256 `059cd1f65cea1c80fcbb045feca4b441c49d6e39ea6ea2210170724c83df74ff`. Rebuilt TypeScript `dist` from `5dd564d…` using TypeScript 5.9.3; all 9 tarball member files match byte-for-byte and the decompressed tar stream matches exactly (SHA-256 `a717028208df7b1d47c11ed2553b558a6c3926d700893ce7c55d02a96bed33b1`). The compressed `.tgz` hash differs because the gzip/deflate stream differs. | Full package content strongly matches a build from the attested source snapshot; `gitHead` is still registry metadata rather than a signed package attestation, and current `v4.1.1` / `main` tags disagree with `5dd564d…`. |
| NuGet `Nexusq` | `4.1.1` | `.nuspec` records `5b8a663…`; package SHA-256 `3254fa2488a61e31f0d177f45b42e02e01700374e924c2e3d25de98d56853b63` and catalog SHA-512 base64 `iJZ0NAoWyAqhB16SiOhHhHN30SDlIh0j9o69qRWv6wbKx67IHQ0/alVEt/7mMbH0pZYzPM8BIL04BaPUAvOjnw==` (matches the downloaded 976,212-byte package; 11 entries including `.signature.p7s`). NuGet catalog records repository commit `5b8a663…` and commit timestamp `2026-10-23T06:15:56.6080761Z`. Managed wrapper `lib/net9.0/Nexusq.dll` SHA-256 `fe3605212145519f51cab9a0b7b5fc000f871a6e26abae7018f8f42bb9ea4d20`; embedded assembly version `4.1.1.0`, informational version `4.1.1+5b8a663…`, PDB path points to the GitHub Actions workspace. Package README matches `bindings/dotnet/src/Nexusq/README.md` at `5b8a663…`. Three non-Windows runtime files match attested GitHub assets byte-for-byte. Windows DLL SHA-256 `0e35010fd2f4b3a83bd8342254cd97a39651c16298cf9db538b69972c48827e3` differs from the attested DLL (`8eb55f8fe890988a5145e19d552b4c48c0b3d310fe43b3367e936c05fe3ee274`), but the 340,992-byte `.text` section is byte-identical (SHA-256 `5bea57cc82198cb3a64635ed5021f4a22a7b3dd5fce9d1f741113f10874b4286`); only 77 bytes differ overall, including timestamps/PDB GUID/import hint values. Exports, imported DLL names and section layout match. | Evidence supports the managed wrapper's declared commit and the same executable native Windows code as the attested release asset. The package includes a NuGet signature file, but its signature/trust chain was not verified here; this is not signed source provenance. Follow-up: Reproduce/verify the complete package with .NET/NuGet tooling on a supported build host; confirm NuGet signature validity and retain package-level source/build provenance. This environment lacks `dotnet`, `nuget`, and `openssl`; do not call the DLL compromised based on its whole-file hash alone. |
| Packagist `lecodev-26/nexusq` | `4.1.1` | Composer source/dist reference `b243950cfbbd3e462e3b387d3ed65255b81ca64e`; downloaded GitHub dist ZIP SHA-256 `6a2e1db0357e0af4c0d11235528c1af836fa9f5f9d3d69492003e8de58f8447e`; all 1,066 files matched that commit byte-for-byte | Strongly identifies the Packagist dist snapshot as `b243950…`; it is distinct from the release-attested commit and current `v4.1.1` tag. |
| PyPI `nexusq` | `4.1.1` | Published sdist SHA-256 `03b8f0d43555aaccc8d10b1d7182bf268a007ad5b235f8e4836c33f818fc800d`; upload time `2026-10-22T01:34:32Z`. Rebuilt with `python -m build --sdist --no-isolation` and Maturin 1.15.0 from `5dd564d…`; generated sdist SHA-256 matches exactly, including generated `pyproject.toml`. | The complete sdist is reproducible byte-for-byte from the release-attested source snapshot `5dd564d…`, which distinguishes it from the `c0899e4…` snapshot whose two Rust files differ. The registry does not provide a signed source attestation, but the content-level source link is now strongly established. |
| pub.dev `nexusq` | `4.1.1` | Archive SHA-256 `8f66fc7c168f0f4403ac12781eb3a00fb4eb0932f4f55b8111dc1cf77e022af0`; published `2026-10-22T02:00:12Z`. All 10 files match `5dd564d…`, `5b8a663…`, `84992f9…`, `c0899e4…`; common files also match `b243950…`. `dart pub publish --dry-run` from `5dd564d…` reports zero warnings. | Package is structurally valid and source files are consistent, but contents do not distinguish a unique source commit; no signed provenance. |
| RubyGems `nexusq` | `4.1.1` | Published gem SHA-256 `f95d9b0efd863ffec18bc49256e39fd32b7dfa92ad0ebe9ed98b953735ed0be3`; created `2026-10-22T01:35:21Z`. Rebuilt with `gem build` from `5dd564d…`; all three payload files match byte-for-byte, but whole-gem hash differs because the generated gem metadata date is `1980-01-02` instead of the published `2026-10-22`. | Payload is reproducible from the source family, but all three files are identical at `5dd564d…`, `5b8a663…`, `84992f9…` and `c0899e4…`, so it does not identify a unique commit. No signed source provenance. |
| crates.io `nexusq` and 16 workspace crates | `4.1.1` | Public sparse-index metadata was read for all 17 crates; all 17 downloaded `.crate` SHA-256 values matched the sparse-index checksums. Embedded `.cargo_vcs_info.json` records four source commits: `5dd564d…` (9 crates), `c0899e4…` (6), `3f8dfb7…` (1), and `38701d5…` (1). | Registry artifacts are confirmed and checksums match index metadata; all 17 `.crate` archives were also reproduced byte-for-byte with `cargo package --no-verify --offline` from their recorded commits. The published version is still split across four recorded source snapshots, and `.cargo_vcs_info.json` is not signed provenance. The 17-crate checksum/commit/MSRV matrix is in [`docs/security/CRATES_IO_4_1_1_INVENTORY.md`](security/CRATES_IO_4_1_1_INVENTORY.md). |
| Maven Central `io.github.lecodev-26:nexusq` | `4.1.1` | POM SHA-256 `e613b0f46fc5d79ff16b161500b4420d46c3efa37e89b5ccf68fcf6bbcf1ede0`; JAR SHA-256 `6074074d097620233ce27fcd470c07858bc3dc1fa839bbd700c66aad984cb593`; sources JAR SHA-256 `2bac8a5bf1074ce73c95947c8fe9751e3c23dc1989fe854a854f5984a6669707`. Rebuilt source JAR from `5dd564d…`: all Java sources and embedded POM match; only generated `pom.properties` timestamp/header differs. `Nexusq.java` matches `5dd564d…`, `5b8a663…`, `84992f9…`, `c0899e4…`, not `b243950…`. | Source content aligns with the attested source family but does not distinguish a unique commit; POM has no SCM revision or signed source provenance. A clean Java binary JAR build has the same 10 entries, but `Nexusq.class` and `Smoke.class` differ bytewise while `javap -c -p` disassembly is identical; manifest and generated `pom.properties` also differ. The Kotlin binary JAR has the same 11 entries and all class files are byte-identical; only manifest and generated `pom.properties` differ. Exact binary JAR byte reproducibility is not achieved in this environment. |
| Maven Central `io.github.lecodev-26:nexusq-kotlin` | `4.1.1` | POM SHA-256 `f511315f658ffd5f58bdbd318205b0666785c1ebe1f4019efe173d6922bd29a2`; JAR SHA-256 `3143e45faf1fe03cf29abc40cf36c9afe04366d2a9615fd18aff99d7a291b3c1`; sources JAR SHA-256 `ed5e78a21c2c00d10c1d02b00dd445027e90357ab9826c69c3d0a3962899f423`. Rebuilt source JAR from `5dd564d…`: Kotlin sources and embedded POM match; only generated `pom.properties` timestamp/header differs. `Nexusq.kt` matches `5dd564d…`, `5b8a663…`, `84992f9…`, `c0899e4…`, not `b243950…`. | Source content aligns with the attested source family but does not distinguish a unique commit; POM has no SCM revision or signed source provenance. The Kotlin binary JAR has the same 11 entries and all class files are byte-identical; only manifest and generated `pom.properties` differ. Exact Kotlin JAR hash differs because of those metadata entries. |
| Swift Package Manager | Repository tag `4.1.1` | Root `Package.swift` and installation docs use the bare semantic-version tag; that tag resolves to `5dd564daab9da1c071b8b134894ea7c4eba95d09` | SwiftPM users selecting `from: "4.1.1"` resolve the bare tag, not `v4.1.1`; the source snapshot is the attested historical commit and differs from current `main`. |
| Go nested module | Separate module version (project docs identify `v0.1.0`) | `bindings/go/nexusq/go.mod` is a nested module; the parent Go module uses a local `replace` and a development `v0.0.0` requirement | Not a `4.1.1` package channel. Verify its nested-module tag/version separately; do not imply it is covered by the 4.1.1 release identity. |

## Public registry provenance/audit signals (read-only)

- **npm:** [`registry metadata`](https://registry.npmjs.org/nexusq/4.1.1) has `gitHead=5dd564d…`, an `integrity` digest matching the downloaded tarball, two `dist.signatures` entries, and `dist.attestations = null`. The signatures are registry integrity metadata; no build-provenance attestation was exposed in this response. The clean content rebuild provides stronger source correlation than `gitHead` alone.
- **PyPI:** [`project JSON`](https://pypi.org/pypi/nexusq/4.1.1/json) exposes the sdist digest and upload time but no per-file provenance object; the exact file endpoint [`/integrity/nexusq/4.1.1/nexusq-4.1.1.tar.gz/provenance`](https://pypi.org/integrity/nexusq/4.1.1/nexusq-4.1.1.tar.gz/provenance) returned HTTP 404 (`No provenance available for nexusq-4.1.1.tar.gz`) on 2026-10-25. The sdist is reproducible from `5dd564d…`, but PyPI has no indexed signed attestation for it. PyPI documents attestations as attached during file upload; do not claim the existing file is attested or re-upload/replace it to simulate historical provenance. Configure trusted publishing and attestations for the next newly versioned distribution.
- **crates.io:** [`version API`](https://crates.io/api/v1/crates/nexusq/4.1.1) records a publish audit action at `2026-10-22T01:54:18.031903Z` by `lecodev-26`, with `github_username_matches=true`, and `trustpub_data=null`. This is useful registry audit metadata, not a signed build/source attestation.
- **pub.dev:** [`version API`](https://pub.dev/api/packages/nexusq/versions/4.1.1) reports `publisher=null` and `verified_publisher=null`; the repository URL and archive digest are present, but no verified publisher identity is recorded there.
- **RubyGems:** [`version API`](https://rubygems.org/api/v2/rubygems/nexusq/versions/4.1.1.json) has empty `metadata` and `source_code_uri=null`; it provides upload time and gem digest, but no source revision.
- **Packagist:** [`package metadata`](https://repo.packagist.org/p2/lecodev-26/nexusq.json) explicitly references source/dist commit `b243950…`, and the downloaded dist reproduces exactly from that commit.
- **NuGet:** [`catalog entry`](https://api.nuget.org/v3/catalog0/data/2026.10.23.06.15.56/nexusq.4.1.1.json) records repository commit `5b8a663…`, commit timestamp, package size and SHA-512; the SHA-512 matches the downloaded package. The package includes `.signature.p7s`, but its signature/trust chain was not verified in this environment. Registry package hash and package signature are not equivalent to source/build provenance.
- **Maven Central:** POMs identify the Git repository but omit an SCM revision; source JAR content identifies the later source family but not a unique commit. No source/build attestation was exposed by the inspected POM/source-JAR metadata.

The manual publishing path was another integrity risk: `publicar.sh` previously relied on the existence of a GitHub release and then published from the current working tree, without verifying a clean tree, tag/HEAD equality, or a maintainer-approved commit. It now fails closed unless the local approval variables and repository approval variable are set, the working tree is clean, and `HEAD`, `vVERSION`, and the approved full SHA agree. The crates.io helper now covers all 17 workspace crates in dependency order plus the separate `nexusq-native-backend` package; registry status checks treat only HTTP 404 as absence and fail closed on other errors. NuGet publication is now manual-dispatch-only from the matching tag, with the same explicit confirmation and full commit SHA gate. These safeguards do not resolve the historical identity mismatch or authorize publication.

The npm, NuGet, and Packagist **registry metadata references** therefore point to three distinct source commits across published 4.1.1 channels (`5dd564d…`, `5b8a663…`, and `b243950…`). This is not proof that each package payload was faithfully built from its declared commit. The version string alone is not a release identity. The crates.io inventory independently confirms four source revisions embedded across 17 published Rust crate archives. These separate observations strengthen the conclusion that 4.1.1 currently names multiple source snapshots across package channels.

## Downloaded asset checksum verification

All 13 assets attached to the GitHub `v4.1.1` release were downloaded to a separate review directory without uploading or modifying anything. Both published checksum manifests verified successfully:

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

- **npm:** tarball SHA-256 `059cd1f65cea1c80fcbb045feca4b441c49d6e39ea6ea2210170724c83df74ff`; registry `gitHead` is `5dd564d…`. Rebuilt `dist` from `5dd564d…` using TypeScript 5.9.3 and repacked with `npm pack --ignore-scripts`: all 9 files match exactly and the uncompressed tar stream is byte-identical (SHA-256 `a717028208df7b1d47c11ed2553b558a6c3926d700893ce7c55d02a96bed33b1`). The compressed tarball hash differs (`f7bb6546…` vs `059cd1f6…`) because the gzip/deflate stream differs; no package member content differed.
- **NuGet:** `.nupkg` SHA-256 `3254fa2488a61e31f0d177f45b42e02e01700374e924c2e3d25de98d56853b63`; embedded `.nuspec` declares commit `5b8a663…`. The Linux x64, Linux ARM64, and macOS ARM64 native libraries match three attested GitHub release assets exactly; the Windows DLL SHA-256 `0e35010fd2f4b3a83bd8342254cd97a39651c16298cf9db538b69972c48827e3` differs from the attested release DLL (`8eb55f8…`), but their 340,992-byte `.text` sections are byte-identical (SHA-256 `5bea57cc82198cb3a64635ed5021f4a22a7b3dd5fce9d1f741113f10874b4286`); 77 byte positions differ in the whole file, consistent with metadata/import-hint changes. This narrows, but does not fully resolve, package build provenance.
- **PyPI:** the published sdist SHA-256 (`03b8f0d43555aaccc8d10b1d7182bf268a007ad5b235f8e4836c33f818fc800d`) was reproduced exactly by `python -m build --sdist --no-isolation` with Maturin 1.15.0 from `5dd564d…`. The generated sdist, including the generated `pyproject.toml`, is byte-for-byte identical to the published archive; this resolves the earlier 389/393 spot-comparison ambiguity in favor of the `5dd564d…` source content. The registry still lacks a signed source attestation.
- **pub.dev:** downloaded archive SHA-256 matches registry metadata (`8f66fc7c168f0f4403ac12781eb3a00fb4eb0932f4f55b8111dc1cf77e022af0`). All 10 archived files match the repository at `5dd564d`, `5b8a663`, and `84992f9`; this package content does not identify one of those commits.
- **RubyGems:** downloaded gem SHA-256 matches the registry-reported SHA (`f95d9b0efd863ffec18bc49256e39fd32b7dfa92ad0ebe9ed98b953735ed0be3`). All three archived files match `5dd564d`, `5b8a663`, and `84992f9`; no source commit is established by this comparison.

- **Packagist:** downloaded GitHub dist ZIP SHA-256 `6a2e1db0357e0af4c0d11235528c1af836fa9f5f9d3d69492003e8de58f8447e`; all 1,066 archived files match commit `b243950…` byte-for-byte.
- **Maven Central:** both `nexusq:4.1.1` and `nexusq-kotlin:4.1.1` are published. Both source JARs were rebuilt from `5dd564d…`; all source files and embedded POMs match, with only generated `pom.properties` build-time metadata differing. Clean binary builds produced the same entry sets: Kotlin `.class` files are byte-identical (only manifest/`pom.properties` differ); Java `Nexusq.class` and `Smoke.class` differ at byte level but their `javap -c -p` disassembly is identical, with manifest/`pom.properties` also differing. The principal wrappers match `5b8a663…`, `84992f9…`, and `c0899e4…`, so no unique commit is established. The POMs do not record an SCM revision.

These spot checks show why matching checksums and a package version are necessary but insufficient for provenance. Keep registry metadata claims separate from independently verified source identity.

### Next evidence required

- [ ] Obtain the publication workflow logs and attestations for each package channel where available.
- [x] Compare source files inside PyPI, pub.dev, RubyGems, and Packagist artifacts against candidate commits; results and limitations are recorded above.
- [ ] Verify the NuGet `.signature.p7s` with NuGet tooling on a supported host; this environment lacks `dotnet`, `nuget`, and `openssl`. The package signature file exists, but no source/build attestation has been established. Windows DLL `.text` is identical to the attested asset and 77 differing bytes are metadata/import-hint locations; package source provenance remains unverified.
- [x] Query crates.io sparse-index metadata and record all 17 published crate checksums, source metadata and MSRV: [`docs/security/CRATES_IO_4_1_1_INVENTORY.md`](security/CRATES_IO_4_1_1_INVENTORY.md).
- [x] Verify Maven Central Java/Kotlin coordinates and digests; rebuild both complete source JARs from `5dd564d…`. All source files and embedded POMs match; only generated `pom.properties` timestamp/header differs. Exact commit remains ambiguous because wrappers also match `5b8a663…`, `84992f9…`, `c0899e4…`, and POMs lack SCM revision. Binary JAR clean-build reproduction remains pending.
- [ ] Reconcile the SwiftPM bare `4.1.1` tag with the `v4.1.1` release tag, and separately document the nested Go module version/tag.
- [ ] Do not infer that every package with version `4.1.1` was built from the same commit; keep each channel's evidence separate until proven otherwise.

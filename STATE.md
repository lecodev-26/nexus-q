# NEXUS-Q v4.1.2 — Release closeout state

**Last verified:** 2026-10-28
**Working copy:** `nexusq-4.1.2-check`
**HEAD/tag:** `v4.1.2` → `8735e5537bc687ee906ed68bdf119fc8956d9439`
**Git state at start:** clean, detached at the annotated release tag.
**Remote changes:** none made. No push, tag mutation, GitHub edit, or package publication was performed during this closeout.

## Release identity and evidence

- GitHub Release [v4.1.2](https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.2) is published (not draft/prerelease), dated 2026-10-27.
- [Release workflow run 40598965703](https://github.com/lecodev-26/nexus-q/actions/runs/40598965703) completed successfully on the exact tag commit. Stable-line gate, cross-platform builds, SDK smoke, reproducible packaging, runtime build jobs, artifact attestation and GitHub Release publication succeeded.
- [MSRV CI pipeline run 40458251043](https://github.com/lecodev-26/nexus-q/actions/runs/40458251043) completed successfully on the same commit; the declared Rust 1.88 MSRV is consistent with the release-tag `Cargo.toml`.
- Published `release-manifest.json` and `nexusq-v4.1.2-provenance.json` both identify commit `8735e5537bc687ee906ed68bdf119fc8956d9439` and version `4.1.2`.
- All 14 public GitHub Release assets matched GitHub's published SHA-256 digest and byte size. The 12 files in the release manifest also matched the manifest and `SHA256SUMS`; all 8 entries in `NATIVE-RUNTIME-SHA256SUMS` matched. `SHA256SUMS` has 13 entries including the release manifest; it does not checksum itself. The SBOM contains 17 components.
- Public status must remain exactly: **“Audit-Ready Release. No production-readiness claim, no FIPS validation, external audit pending.”**

## Registry verification (public endpoints, 2026-10-28)

| Registry / channel | Verified state |
|---|---|
| crates.io | `nexusq`, `nexusq-core`, `nexusq-kernels`, `nexusq-ml-kem`, `nexusq-ml-dsa`, `nexusq-c`, `nexusq-py`, `nexusq-cli`, `nexusq-server` all have `4.1.2` (HTTP 200). `nexusq-native-backend` has independent version `0.1.0` (HTTP 200). |
| crates.io — source-only modules | `nexusq-admin`, `nexusq-enrollment`, `nexusq-ha`, `nexusq-hsm`, `nexusq-ocsp`, `nexusq-tsa`, `nexusq-x509`, `nexusq-pki-cluster` return HTTP 404 for `4.1.2`; do not advertise `cargo add ...@4.1.2`. `nexusq-pki-cluster` has historical `4.1.1` only. |
| PyPI | `nexusq==4.1.2` is present; upload is source distribution only, no platform wheels in this release. |
| npm | `nexusq@4.1.2` is present. |
| NuGet | `Nexusq/4.1.2` package endpoint is present. |
| pub.dev | `nexusq 4.1.2` is present. |
| RubyGems | `nexusq 4.1.2` is present. |
| Packagist | `lecodev-26/nexusq v4.1.2` is present. |
| Maven Central | Java and Kotlin `4.1.2`: POM, JAR, sources JAR, Javadocs JAR, POM/JAR signatures all return HTTP 200. |
| SwiftPM | Git tag `v4.1.2` exists; README now uses `.package(..., from: "4.1.2")`. Historical v4.1.1 tag/provenance caveat remains historical only. |
| Go | `github.com/lecodev-26/nexus-q/bindings/go/nexusq@v0.1.0` is listed by the Go module proxy. The Go module remains independently versioned; runtime pin `4.1.2` and its published checksum set match the release manifest and checksums. |

## Incidents and limitations

- Kotlin Maven upload was accepted by Sonatype with deployment ID `07b675a6-ba25-4e4b-9a40-fb578f99b10d`; the Maven plugin later timed out while polling the deployment. Subsequent Maven Central checks return HTTP 200 for all Kotlin artifact types. Do not redeploy version `4.1.2`.
- The manual Java SDK test run in Termux failed because JNA's native dispatcher requires `libc.so.6`, which is absent from the Android/Termux environment. The release CI SDK smoke job passed; do not describe the local Termux test as passing.
- The eight Rust modules listed above are not published at `4.1.2` on crates.io. They are source-only in this release until separately authorized and published. The release itself is published, but it would be inaccurate to claim that every workspace crate is available from a registry.
- No independent external audit, FIPS 140-3 validation, Common Criteria certification, or production-readiness claim exists.

## Local edits made for this closeout

- `README.md`: refreshed verification dates and release link; corrected the crates.io installation matrix; changed Swift and Go instructions to the current release/version boundary.
- `docs/user/INSTALLATION.md`: pinned available registry installs to explicit versions and marked Go and source-only modules accurately.
- `docs/user/PUBLISHING.md`: changed the Go runtime status from unverified to verified against the published checksums.
- `bindings/go/nexusq/runtime.go`: removed the stale `NOT VERIFIED` comment and recorded the checksum verification date.
- `docs/V4_RELEASE.md`: replaced pre-release planning bullets with observed release, CI, artifact and registry evidence while preserving the v4.1.1 historical section.
- `site/index.html`: changed source/document links from the stale `docs/readme-refresh-full-ci` branch to the immutable `v4.1.2` tag; refreshed the release date and Swift/Go current status.
- `STATE.md`: created this closeout record.

## Closeout change set (2026-10-28)

- Updated root and user documentation to reflect the published v4.1.2 release, actual registry availability, the Rust 1.88 MSRV, and independent Go module versioning.
- Marked eight Rust workspace modules as source-only at v4.1.2 rather than advertising unavailable crates.io packages.
- Updated the project site to link documentation and SDK pages to the immutable `v4.1.2` tag instead of a stale working branch.
- Kept the public claims boundary unchanged: Audit-Ready Release only; no production-readiness claim, no FIPS validation, external audit pending.
- `git diff --check` passes. The change set does not alter release assets, package version declarations, the release workflow, or any tag.
- At the time of this 2026-10-28 closeout, pushes to `main` ran the sequential CI pipeline and the NuGet `workflow_run` workflow could publish after its gates. That historical automation was retired in the separate 2026-11-10 CI architecture reset recorded below.

No release tag is to be moved, deleted, or recreated. No manual release workflow dispatch or package re-publication is part of this closeout.


## CI architecture reset (2026-11-10)

- Removed the former active workflow set from `.github/workflows/` in commit `4b362ec`; the historical copies remain under `.github/workflows-archive/`.
- Replaced the sequential pipeline with `ci.yml` as the only automatic workflow on pushes to `main` and pull requests targeting `main`.
- Reintroduced specialist security, fuzz, correctness, SDK, runtime, native assembly/backend, Arena, and benchmark workflows as independent manual dispatches (SDK/runtime workflows remain callable by the explicit release and NuGet workflows).
- Package publication is now manual and confirmation-gated. Crates.io, PyPI, and RubyGems are grouped in `publish-packages.yml`; NuGet remains a separate OIDC-only workflow. Both verify an annotated version tag, its exact commit, and the matching existing GitHub release manifest.
- `v4-release.yml` is manual-only, defaults to a dry run, requires an explicit publication input, verifies the exact annotated tag, and refuses to overwrite an existing release. Its version constant currently matches the repository's v4.1.2 package line and must be reviewed for a future version bump.
- No workflow was pushed or executed on GitHub as part of this local preparation.

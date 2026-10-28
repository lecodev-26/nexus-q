# Manual SDK publication from Termux

Run `./publicar.sh` from the repository root. The script is deliberately fail-fast: it validates credentials and Maven signing prerequisites before publishing anything, logs to `.publish-dist/`, skips known existing npm/RubyGems/pub.dev versions, and leaves NuGet to its OIDC workflow.

## Local credentials

Create `~/.config/nexusq/publish.env` with mode 600. Copy the variable names from `.github/scripts/publish.env.example`; fill in values locally, never commit the populated file.

- `CRATES_IO_TOKEN`: crates.io publishing token.
- `PYPI_TOKEN`: PyPI API token.
- `NPM_TOKEN`: npm package publishing token.
- `RUBYGEMS_API_KEY`: RubyGems API key.
- `PACKAGIST_USERNAME` and `PACKAGIST_API_TOKEN`: Packagist account and API token.
- Dart uses the existing `dart pub token` login.

## Maven Central

The values in `~/.m2/settings.xml` must be a **Sonatype Central Portal user-token pair**, not necessarily the website login password. Configure a server with id `central` matching the POMs' `publishingServerId`:

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>YOUR_CENTRAL_PORTAL_TOKEN_USERNAME</username>
      <password>YOUR_CENTRAL_PORTAL_TOKEN_PASSWORD</password>
    </server>
  </servers>
</settings>
```

Maven Central also requires signed artifacts. Import a GPG private key locally and publish its public key to a public keyserver before running the script. Do not put the private key or passphrase in this repository.

## Python distribution

On Termux the script builds and publishes the Python source distribution (sdist). It does not pretend that an Android build is a Linux/macOS/Windows wheel; those platform-specific wheels must be built on their matching platforms if they are required for a release.

## NuGet

NuGet is intentionally excluded from local credentials and local publishing. The script triggers `.github/workflows/publish-nuget.yml`, which obtains its API key through GitHub Actions OIDC.

## v4.1.2 release identity and single-run guard

For v4.1.2, `./publicar.sh` fails closed unless the working tree is clean (including untracked files), the local `v4.1.2` tag is annotated, `HEAD` equals the peeled tag commit, and the root Cargo version is exactly `4.1.2`. A lock directory prevents concurrent publishing runs. The script does not create, move, or delete tags. Run it only from the exact release-tag checkout; do not run it from `main`, a moving branch, or an untagged candidate. A stale lock must be investigated before removal; never run two publish processes concurrently.

## PyPI and npm provenance limitation

PyPI and npm do not receive trusted build provenance from this script when packages are published from outside GitHub Actions. Those artifacts are built and uploaded manually, so GitHub Actions attestations do not establish their build provenance. Do not describe those registry artifacts as attested unless a future CI-based publishing flow emits and verifies the relevant provenance. The Go module keeps its independent `v0.x` version line; only its downloaded native runtime is pinned to `4.1.2`.

## Release evidence and claims

The public status is **Audit-Ready Release. No production-readiness claim, no FIPS validation, external audit pending.** Keep the GitHub release manifest, SBOM, provenance record, `SHA256SUMS`, and CI results with the release. Checksums establish byte integrity relative to the published checksum file, not publisher identity by themselves. Independent external audit remains pending; no FIPS validation or production-readiness claim is made.

## Go runtime pin status

Verified on 2026-10-28: the Go module is available as `v0.1.0`; its `4.1.2` runtime pin matches the public `release-manifest.json`, `NATIVE-RUNTIME-SHA256SUMS`, and the release `SHA256SUMS`. All 12 manifest assets were downloaded and their byte sizes and SHA-256 digests matched. The Go module retains independent `v0.x` versioning; do not change its module version to `4.1.2`.

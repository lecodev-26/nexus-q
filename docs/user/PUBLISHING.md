# Manual SDK publication from Termux

Run `./publicar.sh` from the repository root only after a maintainer has explicitly approved the exact release identity. The script validates credentials and Maven signing prerequisites before publishing, logs to `.publish-dist/`, and fails closed if a registry lookup is unavailable or the version's source identity does not match the approved tag.

## Release identity approval gate

Do **not** set these values while the `4.1.1` identity decision is pending. After the maintainer records the chosen full commit SHA and reconciles it with the release tag and artifacts, export the following in the shell used to run the publisher:

```bash
export NEXUSQ_RELEASE_IDENTITY_APPROVED=true
export NEXUSQ_APPROVED_RELEASE_COMMIT="FULL_40_CHARACTER_APPROVED_COMMIT_SHA"
```

The GitHub repository variable `NEXUSQ_RELEASE_IDENTITY_APPROVED` must also be explicitly set to `true` by a maintainer. The local gate requires the official repository remote, a clean working tree, and equality between `HEAD`, `vVERSION`, and the approved SHA. Direct invocation of the crates.io helper applies the same local gate. These checks do not publish anything themselves.

NuGet is now manual-dispatch-only: it must be started from `vVERSION` with the explicit `confirm_release_identity=true` input and the same full approved commit SHA. It no longer publishes automatically from a `main` CI run.

The GitHub stable-release workflow uses the same explicit identity decision: on `v4.1.1`, supply `confirm_release_identity=true`, set the repository approval variable only after the decision, and enter `approved_release_commit` as the full SHA selected by the maintainer. The workflow rejects a SHA that differs from the tag target and checked-out commit. This guard does not resolve the existing published-release mismatch by itself.

## Registry behavior and partial publication

The publisher checks the exact version before pushing to crates.io, npm, RubyGems, pub.dev, and Maven Central; lookup failures and unexpected HTTP responses stop publication rather than being treated as a missing version. Maven Central search responses are schema-validated as well, so malformed JSON cannot be interpreted as permission to publish. PyPI uses Twine's `--skip-existing`; NuGet uses `--skip-duplicate` in its separately gated OIDC workflow. Packagist receives a repository refresh request rather than a direct package upload.

Publication across registries is **not atomic**. If a later registry fails, earlier registries may already contain the version. Stop at the first error, record which registries completed, verify the published artifacts and provenance, and resume only after an explicit review; do not blindly rerun the entire script. The script does not roll back immutable registry releases. Go and Swift consumers resolve Git tags, so their source identity must be reconciled separately from registry packages.

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

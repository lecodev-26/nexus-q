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

NuGet is intentionally excluded from local credentials and local publishing. The script triggers `.github/workflows/publicar-nuget.yml`, which obtains its API key through GitHub Actions OIDC.

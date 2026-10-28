# Installation

NEXUS-Q v4.1.2 is the current published release. This matrix was checked on 2026-10-28. Registry availability is not proof that every package was built from the same Git commit; release provenance and artifact hashes are documented in `docs/V4_RELEASE.md`. The v4.1.1 tag/provenance caveat is historical.

## From package registries

| Channel | Install |
|---|---|
| Rust library (all-in-one metacrate) | `cargo add nexusq@4.1.2` — [crates.io](https://crates.io/crates/nexusq) |
| Rust library (core only) | `cargo add nexusq-core@4.1.2` — [crates.io](https://crates.io/crates/nexusq-core) |
| Rust kernels | `cargo add nexusq-kernels@4.1.2` — [crates.io](https://crates.io/crates/nexusq-kernels) |
| Rust ML-KEM | `cargo add nexusq-ml-kem@4.1.2` — [crates.io](https://crates.io/crates/nexusq-ml-kem) |
| Rust ML-DSA | `cargo add nexusq-ml-dsa@4.1.2` — [crates.io](https://crates.io/crates/nexusq-ml-dsa) |
| Rust native backend (experimental, opt-in) | `cargo add nexusq-native-backend@0.1.0` — [crates.io](https://crates.io/crates/nexusq-native-backend); independent version line, not enabled by default. |
| Rust admin/PKI/HSM/enrollment/HA/OCSP/TSA/X.509 modules | Source-only at v4.1.2; not published on crates.io. Build from the checkout with `cargo build --workspace --release`. `nexusq-pki-cluster` has only a historical 4.1.1 registry version. |
| Rust CLI | `cargo install nexusq-cli --version 4.1.2` — [crates.io](https://crates.io/crates/nexusq-cli) |
| Rust server | `cargo install nexusq-server --version 4.1.2` — [crates.io](https://crates.io/crates/nexusq-server) |
| C / C++ SDK | `cargo add nexusq-c@4.1.2` for Rust consumers; for a C ABI install, use `cargo cinstall -p nexusq-c` with [cargo-c](https://github.com/lu-zero/cargo-c), or build from this checkout. |
| Python | `pip install nexusq==4.1.2` — [PyPI](https://pypi.org/project/nexusq/4.1.2/); source distribution only, no platform wheel in this upload. |
| TypeScript / Node.js | `npm install nexusq@4.1.2` — [npm](https://www.npmjs.com/package/nexusq/v/4.1.2) |
| Java | `io.github.lecodev-26:nexusq:4.1.2` — [Maven Central artifacts](https://repo.maven.apache.org/maven2/io/github/lecodev-26/nexusq/4.1.2/) |
| Kotlin | `io.github.lecodev-26:nexusq-kotlin:4.1.2` — [Maven Central artifacts](https://repo.maven.apache.org/maven2/io/github/lecodev-26/nexusq-kotlin/4.1.2/) |
| C# / .NET | `dotnet add package Nexusq --version 4.1.2` — [NuGet](https://www.nuget.org/packages/Nexusq/4.1.2) |
| Swift / SwiftPM | `.package(url: "https://github.com/lecodev-26/nexus-q.git", from: "4.1.2")`, product `Nexusq`; tag [`v4.1.2`](https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.2) exists. The v4.1.1 caveat is historical. |
| Dart / Flutter | `dart pub add nexusq:^4.1.2` — [pub.dev](https://pub.dev/packages/nexusq/versions/4.1.2) |
| Go | `go get github.com/lecodev-26/nexus-q/bindings/go/nexusq@v0.1.0` — Go module version is independent (`v0.1.0`); runtime `4.1.2` and its SHA-256 checksums verified against the GitHub release — [pkg.go.dev](https://pkg.go.dev/github.com/lecodev-26/nexus-q/bindings/go/nexusq). |
| PHP | `composer require lecodev-26/nexusq:4.1.2` — [Packagist](https://packagist.org/packages/lecodev-26/nexusq) |
| Ruby | `gem install nexusq -v 4.1.2` — [RubyGems](https://rubygems.org/gems/nexusq/versions/4.1.2) |

The Go, PHP, Ruby, TypeScript, Java, Kotlin and Dart SDKs resolve or download a version-matched runtime on supported targets; downloads verify SHA-256. The Go runtime assets and their published checksums were verified against the v4.1.2 release on 2026-10-28. Registry presence does not prove provenance alignment with a specific Git commit. Go uses a pure-Go loader and does not require cgo. Dart uses `curl` for its synchronous first-use download. `NEXUSQ_LIBRARY` remains an advanced override for development and offline tests. The `nexusq` metacrate groups the published Rust library crates (`nexusq-core`, `nexusq-kernels`, `nexusq-ml-kem`, `nexusq-ml-dsa`) so a single `cargo add nexusq` pulls them all in; prefer individual crates for a minimal dependency tree. The Python package is a self-contained PyO3 native extension. The GitHub release includes the CLI/server package and separate versioned C ABI runtime archives/assets.

## From source

Requirements:

- Rust 1.88 or newer for v4.1.2 (`rust-version = "1.88"` in the release-tag `Cargo.toml`). The Rust 1.88.0 MSRV pipeline passed on the exact release commit: [CI run 40458251043](https://github.com/lecodev-26/nexus-q/actions/runs/40458251043).
- Git.

Build:

    cargo build --workspace --release

The resulting binaries are target/release/nexusq and target/release/nexusq-server.

## Release archive

Create the portable release package:

    cargo build --workspace --release
    ./deploy/package-release.sh

The package contains versioned binaries, a non-secret server configuration example, deployment/server documentation, and SHA-256 manifests.

Verify both the archive checksum and the internal manifest before installation.

## Installation layout

A portable deployment can use:

    /opt/nexusq/bin/nexusq
    /opt/nexusq/bin/nexusq-server
    /etc/nexusq/server.env
    /var/lib/nexusq/vault.nqx
    /var/log/nexusq/

The exact filesystem layout is an operational convention, not a package-manager requirement.

## Production prerequisites

Before starting the server:

1. Create or provision the vault.
2. Create a production bearer token with at least 32 bytes of entropy.
3. Store the token outside source control.
4. Set restrictive permissions on the configuration and vault.
5. Keep the server bound to loopback unless a trusted TLS termination layer is present.
6. Configure a supervisor to allow graceful SIGTERM/SIGINT shutdown.

Docker, systemd, .deb, .rpm, and registry publication are not required by the current deployment boundary. For registry installation channels, see the table above; it lists currently available registry packages; their availability does not change the deployment boundary or imply any validation claim.


The reproducible [GitHub v4.1.2 release](https://github.com/lecodev-26/nexus-q/releases/tag/v4.1.2) includes versioned C ABI runtime archives and
direct per-platform assets, each with `include/nexusq.h` and the matching library
(`lib/libnexusq.so`, `lib/libnexusq.dylib`, or `lib/nexusq.dll`). These ordinary
SDK artifacts use the default RustCrypto provider. The separate native-backend
CI artifacts are experimental and are not substituted into ordinary SDK packages.
See [native runtime packaging](../NATIVE_RUNTIME_PACKAGING.md) for exact targets,
ABI/libc limits, download behavior, and remaining platform limitations.

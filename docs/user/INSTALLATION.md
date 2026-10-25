# Installation

NEXUS-Q 4.1.1 is available through several package registries and can also be built from source. Registry availability is not proof that every package was built from the same Git commit. The bare `4.1.1` tag and verified GitHub release attestation identify commit `5dd564d`, while `v4.1.1` and current `main` resolve to `84992f9`; registry package metadata also records other source snapshots. The public SBOM is still incomplete. Review the [release-integrity inventory](../RELEASE_INTEGRITY_INVENTORY.md) and root README status note before relying on release-archive provenance.

## From package registries

| Channel | Install | Status |
|---|---|---|
| Rust library (all-in-one metacrate) | `cargo add nexusq` | Available — crates.io |
| Rust library (core only) | `cargo add nexusq-core` | Available — crates.io |
| Rust CLI | `cargo install nexusq-cli` | Available — crates.io |
| Rust server | `cargo install nexusq-server` | Available — crates.io |
| C / C++ SDK | `cargo cinstall -p nexusq-c` (requires [cargo-c](https://github.com/lu-zero/cargo-c)), or build the C library from source | Available — crates.io |
| Python | `pip install nexusq` | Available — PyPI |
| TypeScript / Node.js | `npm install nexusq` | Published 4.1.1 on npm |
| Java | `io.github.lecodev-26:nexusq:4.1.1` | Published 4.1.1 on Maven Central |
| Kotlin | `io.github.lecodev-26:nexusq-kotlin:4.1.1` | Published 4.1.1 on Maven Central |
| C# / .NET | `dotnet add package Nexusq` | Published 4.1.1; see runtime assets and workflow evidence in root README |
| Swift | Swift Package Manager package at this repository (`bindings/swift`) | Bare tag `4.1.1` resolves to commit `5dd564d`, while `v4.1.1` resolves to current `main`; verify the exact tag before consuming |
| Dart / Flutter | `dart pub add nexusq` | Published 4.1.1 on pub.dev |
| Go | `go get github.com/lecodev-26/nexus-q/bindings/go/nexusq` | Available — pkg.go.dev |
| PHP | `composer require lecodev-26/nexusq` | Available — Packagist |
| Ruby | `gem install nexusq` | Available — RubyGems.org |

The Go, PHP, Ruby, TypeScript, Java, Kotlin and Dart SDKs resolve or download a version-matched runtime on supported targets; downloads verify SHA-256. Registry presence does not prove provenance alignment with a specific Git commit. Go uses a pure-Go loader and does not require cgo. Dart uses `curl` for its synchronous first-use download. `NEXUSQ_LIBRARY` remains an advanced override for development and offline tests. The `nexusq` metacrate groups the published Rust library crates (`nexusq-core`, `nexusq-kernels`, `nexusq-ml-kem`, `nexusq-ml-dsa`) so a single `cargo add nexusq` pulls them all in; prefer individual crates for a minimal dependency tree. The Python package is a self-contained PyO3 native extension. The GitHub release includes the CLI/server package and separate versioned C ABI runtime archives/assets.

## From source

Requirements:

- Rust 1.88 or newer for current `main` (the published release-tag manifest declares Rust 1.85; do not infer that requirement for all package builds).
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


The reproducible GitHub release includes versioned C ABI runtime archives and
direct per-platform assets, each with `include/nexusq.h` and the matching library
(`lib/libnexusq.so`, `lib/libnexusq.dylib`, or `lib/nexusq.dll`). These ordinary
SDK artifacts use the default RustCrypto provider. The separate native-backend
CI artifacts are experimental and are not substituted into ordinary SDK packages.
See [native runtime packaging](../NATIVE_RUNTIME_PACKAGING.md) for exact targets,
ABI/libc limits, download behavior, and remaining platform limitations.

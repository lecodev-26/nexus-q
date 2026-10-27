# Installation

NEXUS-Q 4.1.2 is distributed through several package registries and can also be built from source. Registry availability is not proof that every package was built from the same Git commit. The historical v4.1.1 tag/provenance caveat is documented in `docs/V4_RELEASE.md`; v4.1.2 installation coordinates are listed below, with provenance tracked separately.

## From package registries

| Channel | Install |
|---|---|
| Rust library (all-in-one metacrate) | `cargo add nexusq` — crates.io |
| Rust library (core only) | `cargo add nexusq-core` — crates.io |
| Rust CLI | `cargo install nexusq-cli` — crates.io |
| Rust server | `cargo install nexusq-server` — crates.io |
| C / C++ SDK | `cargo cinstall -p nexusq-c` (requires [cargo-c](https://github.com/lu-zero/cargo-c)), or build the C library from source — crates.io |
| Python | `pip install nexusq` — PyPI |
| TypeScript / Node.js | `npm install nexusq` — 4.1.2 on npm |
| Java | `io.github.lecodev-26:nexusq:4.1.2` — 4.1.2 on Maven Central |
| Kotlin | `io.github.lecodev-26:nexusq-kotlin:4.1.2` — 4.1.2 on Maven Central |
| C# / .NET | `dotnet add package Nexusq` — 4.1.2; see runtime assets and workflow evidence in root README |
| Swift (historical tag caveat) | Swift Package Manager package at this repository (`bindings/swift`) — Historical v4.1.1 note: bare tag `4.1.1` resolves to `5dd564d`, while mutable `v4.1.1` follows `main`; verify exact tag |
| Dart / Flutter | `dart pub add nexusq` — 4.1.2 on pub.dev |
| Go | `go get github.com/lecodev-26/nexus-q/bindings/go/nexusq` — pkg.go.dev; runtime pin 4.1.2: **NO VERIFICADO** |
| PHP | `composer require lecodev-26/nexusq` — Packagist |
| Ruby | `gem install nexusq` — RubyGems.org |

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

# Installation

NEXUS-Q can be installed from the language package registries (publication of the 4.1.0 stable line in progress) or built from source.

## From package registries

| Channel | Install | Status |
|---|---|---|
| Rust library | `cargo add nexusq-core` | Publication in progress — crates.io |
| Rust CLI | `cargo install nexusq-cli` | Publication in progress — crates.io |
| Rust server | `cargo install nexusq-server` | Publication in progress — crates.io |
| C / C++ SDK | `cargo cinstall -p nexusq-c` (requires [cargo-c](https://github.com/lu-zero/cargo-c)), or the GitHub release tarball | Publication in progress — crates.io |
| Python | `pip install nexusq` | Publication in progress — PyPI |
| Go | `go get github.com/lecodev-26/nexus-q/bindings/go/nexusq` | Publication in progress — pkg.go.dev |
| PHP | `composer require lecodev-26/nexusq` | Publication in progress — Packagist |
| Ruby | `gem install nexusq` | Publication in progress — RubyGems.org |

The Go, PHP and Ruby bindings are thin FFI wrappers over the C SDK (`libnexusq`); build and install the C library first. The Python package is a native extension module built from `crates/nexusq-py` (PyO3).

## From source

Requirements:

- Rust 1.85 or newer.
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

Docker, systemd, .deb, .rpm, and registry publication are not required by the current deployment boundary. For the supported registry installation channels of the 4.1.0 line see the table above; their availability does not change the deployment boundary or imply any validation claim.

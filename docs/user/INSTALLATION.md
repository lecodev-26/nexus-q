# Installation

NEXUS-Q currently uses a package-manager-neutral installation model.

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

Docker, systemd, .deb, .rpm, and registry publication are not required by the current deployment boundary.

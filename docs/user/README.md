# NEXUS-Q User Guide

NEXUS-Q is a Rust-based cryptographic security engine with a CLI, library API, authenticated HTTP server, and native bindings.

This guide describes the current implemented surface. Features described as CI-only, planned, hardware-dependent, or future are not presented as available local features.

## Start here

1. [Getting Started](GETTING_STARTED.md)
2. [Installation](INSTALLATION.md)
3. [CLI Guide](CLI.md)
4. [Vault Guide](VAULT.md)
5. [Crypto Guide](CRYPTO.md)
6. [Identity Guide](IDENTITY.md)
7. [API Guide](API.md)
8. [SDK Guide](SDK.md)
9. [Hardware Guide](HARDWARE.md)
10. [Security Guide](SECURITY.md)
11. [Deployment Guide](DEPLOYMENT.md)
12. [Troubleshooting](TROUBLESHOOTING.md)

## Current support boundary

The local delivery boundary includes the Rust core, CLI, C FFI, limited Python binding, and authenticated HTTP server. Other language SDKs and external publication are not claimed as shipped.

The default server bind is loopback. Remote exposure requires a trusted TLS termination boundary; NEXUS-Q does not terminate TLS itself.

## Security rule

Never put production passwords, bearer tokens, private keys, vault files, or generated logs into source control or documentation. Examples use placeholders only.

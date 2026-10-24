# NEXUS-Q User Guide

NEXUS-Q is a Rust-based cryptographic security engine with a CLI, library API, authenticated HTTP server, and native bindings.

**Project status:** the V4 native backend is experimental and opt-in. It is wired into `nexusq-core` behind the `native-backend` feature, but the default core build, CLI, server and SDK production paths continue to use RustCrypto. The repository and its engineering releases do not claim production readiness, independent audit, or FIPS validation. See the root README and [`docs/performance/NATIVE_BACKEND_FEATURE.md`](../performance/NATIVE_BACKEND_FEATURE.md) for the current boundary.

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

The repository includes the Rust core, CLI, C FFI, Python binding and authenticated HTTP server, along with language bindings under `bindings/`. Package availability, platform support and release provenance vary by ecosystem; verify each package against the root README installation table and its binding-specific instructions.

The default server bind is loopback. Remote exposure requires a trusted TLS termination boundary; NEXUS-Q does not terminate TLS itself.

## Security rule

Never put production passwords, bearer tokens, private keys, vault files, or generated logs into source control or documentation. Examples use placeholders only.

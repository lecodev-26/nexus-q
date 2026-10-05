# NEXUS-Q Deployment

This document defines the supported local/release deployment profile for the NEXUS-Q server. It is independent of GitHub, package registries, or a particular init system.

## Profiles

### Development

Use a local vault and loopback binding.

Build: cargo build
Server: target/debug/nexusq-server
Bind: 127.0.0.1:8443 (or another loopback port)
TLS termination: not required
Logs: RUST_LOG=nexusq_server=debug
Secrets: supplied through the environment or an external secret mechanism

Development deployments must never commit populated environment files, vaults, private keys, bearer tokens, or generated logs.

### Release

Build the workspace in release mode:

    cargo build --workspace --release

The server binary is target/release/nexusq-server.
The CLI binary is target/release/nexusq.

For a release deployment, keep application binaries separate from mutable state. A recommended layout is:

    /opt/nexusq/bin/nexusq
    /opt/nexusq/bin/nexusq-server
    /etc/nexusq/server.env
    /var/lib/nexusq/vault.nqx
    /var/log/nexusq/

The exact paths may be changed for a platform, but the separation of code, configuration/secrets, and mutable vault state should be preserved.

## Configuration

Start from deploy/nexusq-server.env.example and populate it through the deployment secret-management mechanism. The server requires NEXUSQ_VAULT_PATH and NEXUSQ_SERVER_TOKEN with at least 32 bytes.

Optional settings and defaults are documented in docs/SERVER.md.

Do not put the bearer token in command history, source control, process arguments, HTTP diagnostics, or logs.

## Network boundary

The safe default is loopback:

    NEXUSQ_SERVER_ADDR=127.0.0.1:8443

For remote exposure, TLS/mTLS must terminate at a trusted boundary and the deployment must explicitly set NEXUSQ_TRUSTED_TLS_TERMINATION=1.

The NEXUS-Q server itself does not currently provide native TLS termination. Never use the trusted-termination flag merely to bypass the bind check.

## Permissions

A production deployment should use a dedicated service identity.

| Resource | Recommended access |
| --- | --- |
| nexusq / nexusq-server | service user: execute/read |
| server environment file | service user: read; administrators: modify |
| vault file | service user: read/write; administrators: restricted |
| log directory | service user: write; administrators: read |
| parent deployment directories | service user: traverse only where possible |

The deployment must not make the vault, bearer token, or private-key material world-readable.

## Startup sequence

1. Provision the dedicated service identity and directories.
2. Install the release binaries.
3. Provision the vault using the NEXUS-Q CLI or an existing trusted vault.
4. Provision the bearer token through the deployment secret mechanism.
5. Load the environment configuration.
6. Start nexusq-server.
7. Confirm /health and /readyz.
8. Confirm /metrics is reachable only from the intended monitoring boundary.
9. Put the service behind the trusted TLS boundary before allowing remote clients.

## Shutdown and recovery

On Unix, SIGTERM and SIGINT initiate graceful shutdown. The HTTP server stops accepting work and the process then releases its application state, including the vault/session resources owned by the process.

Deployment supervisors should use a normal termination signal and allow graceful shutdown before escalating to a forced kill.

If startup fails because configuration is invalid, do not weaken the configuration checks. Correct the environment, filesystem permissions, vault path, or network boundary and restart.

## Health and observability

Liveness: /health
Readiness: /readyz
Metrics: /metrics
Logs: RUST_LOG

Do not expose /metrics or administrative endpoints beyond the intended monitoring/management boundary.

## Artifact boundary

Phase 19 prepares deployment artifacts and procedures only. It does not publish GitHub repositories, crates, PyPI packages, SDK packages, or a NEXUS-Q v1.0 release. Publication remains a later release-stage gate.

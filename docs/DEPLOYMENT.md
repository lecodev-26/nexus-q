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

## Operational commands

### Build

Development:

    cargo build --workspace

Release:

    cargo build --workspace --release

Package the release artifacts locally:

    ./deploy/package-release.sh

The package script writes a versioned `.tar.gz` and an adjacent SHA-256 file
under `dist/`. It never publishes the artifact.

### Install

Unpack the archive into the platform's application directory and keep the
following outside the application tree:

- the populated server environment file;
- the vault and other mutable state;
- service logs.

Provision `NEXUSQ_VAULT_PATH` and `NEXUSQ_SERVER_TOKEN` through the platform's
secret/configuration mechanism. The token must be at least 32 bytes.

### Run

A minimal release invocation is:

    RUST_LOG=nexusq_server=info ./nexusq-server

For production-like deployment, load the populated environment file through
the platform's process manager instead of placing secrets on the command line.

The server defaults to `127.0.0.1:8443`. A non-loopback bind is rejected unless
`NEXUSQ_TRUSTED_TLS_TERMINATION=1` explicitly declares a trusted TLS/mTLS
termination boundary.

## Operational probes

Use the following unauthenticated endpoints for process supervision and load
balancer/monitoring checks:

| Endpoint | Purpose |
| --- | --- |
| `/health` | Liveness: the HTTP service is responding. |
| `/v1/health` | Versioned liveness endpoint. |
| `/readyz` | Readiness: the service is ready to accept requests. |
| `/v1/ready` | Versioned readiness endpoint. |
| `/metrics` | Prometheus-style aggregate operational metrics. |

`/metrics` should be reachable only from the intended monitoring boundary.
Do not expose health or metrics endpoints directly to an untrusted network.

## Logs

Logging is controlled through `RUST_LOG`; the documented default for the
server is `nexusq_server=info`. Logs may include request IDs, operation names,
latency and aggregate operational information, but must not contain bearer
tokens, passwords, plaintext payloads, vault contents, or private key material.

## Backup and recovery

The vault is mutable application state and must be backed up using the
NEXUS-Q backup/storage procedures appropriate to the deployment. Backups must
be encrypted/protected according to the deployment's security policy and must
not be stored in the release artifact directory.

Recovery should use a trusted vault backup, restore it with restrictive file
permissions, point `NEXUSQ_VAULT_PATH` to the restored vault, provision a fresh
valid server token when required by the deployment policy, and verify
`/health` and `/readyz` before accepting traffic.

Do not treat a server binary, environment file, log, or package checksum as a
substitute for a vault backup.

## Service supervisor example

NEXUS-Q does not require Docker, systemd, or another specific supervisor.
A supervisor should provide the equivalent lifecycle properties:

1. start `nexusq-server` with the populated environment;
2. keep the vault and configuration outside the binary directory;
3. monitor `/health` and `/readyz`;
4. collect logs without exposing secrets;
5. send SIGTERM for normal Unix shutdown;
6. allow the graceful shutdown interval before escalation;
7. restart only after configuration and vault availability are verified.

This is intentionally a portable operational contract rather than a mandatory
service-unit format.


### Trusted proxy configuration

When remote trusted TLS termination is enabled, also set `NEXUSQ_TRUSTED_PROXY_IPS` to the comma-separated IP addresses of the reverse proxies that may connect directly to NEXUS-Q. X-Forwarded-For is ignored for security decisions unless the peer socket is loopback or matches this allowlist; the address is selected by walking the chain from the right and skipping trusted proxy hops. This prevents direct clients from spoofing X-Forwarded-For to evade the rate limiter.

# NEXUS-Q Server

nexusq-server is the network service wrapper around nexusq-core. It does not
implement cryptography itself.

## Current service boundary

The server provides:

- /health and /v1/health without authentication.
- /v1/version without authentication.
- Bearer-token authentication for protected endpoints.
- Constant-time bearer-token comparison.
- A minimum 32-byte bearer secret at startup.
- Per-client request rate limiting.
- Vault lock/unlock/status.
- Key listing, creation, rotation, revocation and destruction.
- Identity signing and signature verification.
- Envelope encryption and decryption.
- Audit inspection and full audit-chain verification.
- Core policy enforcement through nexusq-core.
- Graceful shutdown on SIGTERM/SIGINT (Unix) or SIGINT (non-Unix).
- Loopback-only TCP by default.

Protected operations are serialized through the in-process vault session so
secret state is not concurrently mutated by multiple requests.

## Configuration

Required:

- NEXUSQ_VAULT_PATH — path to an existing NEXUS-Q vault.
- NEXUSQ_SERVER_TOKEN — bearer secret, minimum 32 bytes.

Optional:

- NEXUSQ_SERVER_ADDR — TCP bind address, default 127.0.0.1:8443.
- NEXUSQ_SERVER_RATE_LIMIT — maximum requests per client per 60-second window, default 60. Must be greater than zero.
- NEXUSQ_SERVER_MAX_BODY_BYTES — maximum HTTP request body size, default 1048576 (1 MiB). Must be greater than zero.
- NEXUSQ_TRUSTED_TLS_TERMINATION=1 — required before binding a non-loopback
  address. This explicitly declares that TLS/mTLS termination is performed by
  a trusted deployment boundary.
- RUST_LOG — tracing filter.

The server refuses to expose plaintext TCP remotely by accident. Invalid numeric deployment settings are rejected at startup rather than silently falling back.

## Transport security

Remote deployments must terminate TLS before traffic reaches the service.
A non-loopback bind without NEXUSQ_TRUSTED_TLS_TERMINATION=1 is rejected.

The direct server currently implements bearer authentication. Native mTLS,
signed-challenge authentication and Unix-domain-socket transport remain future
transport/authentication work. The current HTTP surface includes the audit
inspection and audit-chain verification endpoints.

## Error handling

External responses deliberately avoid returning core error details. Internal
failures are logged server-side without logging passwords, bearer tokens,
plaintext payloads or key material.

## Architecture rule

All cryptographic and policy decisions remain in nexusq-core. The server is
an authenticated transport/orchestration layer only.

## Shutdown

The server uses graceful shutdown through Tokio. On Unix deployments, both SIGTERM and SIGINT initiate the same shutdown path; on non-Unix targets, SIGINT is used.

The process does not log or expose the bearer token during startup or shutdown. Once the HTTP server exits, the application state is dropped, releasing the vault/session resources owned by the process.

## Operational interface

For deployment and process supervision, use:

- `/health` and `/v1/health` for liveness;
- `/readyz` and `/v1/ready` for readiness;
- `/metrics` for aggregate Prometheus-style metrics;
- `X-Request-Id` on HTTP responses for request correlation.

Health/readiness and metrics responses do not require bearer authentication,
but the endpoints should remain within the intended deployment/monitoring
trust boundary. Do not expose `/metrics` to untrusted networks.

## Logs and secrets

`RUST_LOG` controls tracing filters. The server may log operation names,
request IDs, status and latency, but must not log bearer tokens, passwords,
plaintext payloads, vault contents, private keys, or other secret material.

Do not pass `NEXUSQ_SERVER_TOKEN` as a process argument. Load it through the
platform's environment/secret mechanism.

## Deployment lifecycle

Build a release with:

    cargo build --workspace --release

Then use `deploy/package-release.sh` to assemble a package-neutral deployment
artifact. Keep binaries, configuration/secrets, mutable vault state, and logs
in separate filesystem areas.

A deployment should verify liveness/readiness after startup, keep metrics
inside the monitoring boundary, and use SIGTERM/SIGINT for graceful Unix
shutdown. For recovery, restore a trusted vault backup with restrictive
permissions and verify the probes before returning the service to traffic.

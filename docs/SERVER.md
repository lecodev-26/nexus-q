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
- Graceful shutdown on SIGINT.
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

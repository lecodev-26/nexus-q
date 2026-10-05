# API Guide

NEXUS-Q exposes three practical API layers in the current delivery boundary:

1. Rust library.
2. CLI.
3. Authenticated HTTP server.

## Rust

The core API is centered on `Vault` and `Session`:

```rust
let vault = Vault::create(path, password, Some("example".into()))?;
let session = vault.unlock(password)?;
let key_id = session.generate_key(Algorithm::Ed25519, Purpose::Sign)?;
let signature = session.identity_sign(&identity_id, message)?;
let vault = session.lock()?;
```

Use the crate source and [Public API](../API.md) for exact types and signatures.

## HTTP server

The server exposes:

```text
GET  /health
GET  /v1/health
GET  /readyz
GET  /v1/ready
GET  /v1/version
GET  /metrics

POST /v1/vault/unlock
POST /v1/vault/lock
GET  /v1/vault/status
GET  /v1/keys
POST /v1/keys
POST /v1/keys/{key_id}/rotate
POST /v1/keys/{key_id}/revoke
POST /v1/keys/{key_id}/destroy
POST /v1/encrypt
POST /v1/decrypt
POST /v1/sign
POST /v1/verify
GET  /v1/audit
POST /v1/audit/verify
```

Protected endpoints require the configured bearer token:

```text
Authorization: Bearer <server-token>
```

The token is configured through `NEXUSQ_SERVER_TOKEN` and must be at least 32 bytes.

The health, readiness, version, and metrics endpoints are intentionally public.

## Transport boundary

The server itself does not terminate TLS. The safe default is loopback. For a remote deployment, place a trusted TLS/mTLS termination layer in front and set `NEXUSQ_TRUSTED_TLS_TERMINATION=1` only when that boundary is actually present.

See [Server](../SERVER.md) and [Deployment](../DEPLOYMENT.md).

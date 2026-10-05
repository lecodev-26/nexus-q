# Deployment Guide

Phase 19 defines the portable deployment boundary.

## Release build

```bash
cargo build --workspace --release
./deploy/package-release.sh
```

The package contains:

- `nexusq`;
- `nexusq-server`;
- non-secret configuration example;
- deployment/server documentation;
- SHA-256 manifests.

It does not contain production secrets, vaults, private keys, or logs.

## Configuration

Required:

```text
NEXUSQ_VAULT_PATH
NEXUSQ_SERVER_TOKEN
```

Optional:

```text
NEXUSQ_SERVER_ADDR=127.0.0.1:8443
NEXUSQ_SERVER_RATE_LIMIT=60
NEXUSQ_SERVER_MAX_BODY_BYTES=1048576
NEXUSQ_TRUSTED_TLS_TERMINATION=0
RUST_LOG=nexusq_server=info
```

The server rejects non-loopback binds unless trusted TLS termination is explicitly enabled.

## Operational endpoints

- `/health` and `/v1/health`: liveness.
- `/readyz` and `/v1/ready`: readiness.
- `/metrics`: Prometheus-compatible aggregate metrics.
- `X-Request-Id`: request correlation header.

## Shutdown

Unix deployments handle SIGTERM and SIGINT through the graceful shutdown path. Supervisors should allow the process to terminate gracefully.

## Backup and recovery

Protect the vault, audit data, configuration secrets, and backups according to the same sensitivity boundary. Recovery procedures must restore data and permissions before exposing the service.

For the complete operational procedure see [Deployment](../DEPLOYMENT.md).

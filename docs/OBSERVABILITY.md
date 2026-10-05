# Observability

NEXUS-Q exposes operational telemetry without exposing cryptographic material.

## Scope

The observability layer is deliberately local and dependency-light. It provides:

- structured tracing logs in the server;
- request correlation through X-Request-Id;
- aggregate operation/request counters and latency totals;
- Prometheus-compatible text metrics at /metrics;
- liveness at /health and readiness at /readyz;
- CLI nexusq health and nexusq diagnostics commands.

The metrics exposition follows the Prometheus text exposition format 0.0.4.
Prometheus can derive operations/sec from nexusq_operations_total, for example
with rate(nexusq_operations_total[5m]).

## Metrics

The server exposes these aggregate metrics:

| Metric | Type | Meaning |
|---|---|---|
| nexusq_operations_total | counter | All observed operations |
| nexusq_errors_total | counter | Failed operations |
| nexusq_operation_duration_seconds_sum | summary sum | Total operation duration |
| nexusq_operation_duration_seconds_count | summary count | Number of duration observations |
| nexusq_operation_latency_seconds | gauge | Average observed operation latency |
| nexusq_requests_total | counter | HTTP requests |
| nexusq_request_errors_total | counter | HTTP requests with non-success status |
| nexusq_request_duration_seconds_sum | summary sum | Total HTTP request duration |
| nexusq_request_duration_seconds_count | summary count | Number of HTTP duration observations |
| nexusq_request_latency_seconds | gauge | Average HTTP request latency |
| nexusq_key_operations_total | counter | Key lifecycle/usage operations |
| nexusq_vault_operations_total | counter | Vault operations |
| nexusq_hardware_status | gauge | Hardware backend availability (1/0) |
| nexusq_uptime_seconds | gauge | Process uptime |

No user-controlled identifiers are emitted as metric labels. This avoids
high-cardinality and accidental disclosure of key IDs, paths, client addresses,
or request payloads.

## Logs and correlation

Server logs contain only operational metadata such as:

- request ID;
- normalized operation name;
- HTTP status;
- duration;
- startup/shutdown and safe subsystem errors.

The server never logs:

- passwords or bearer tokens;
- plaintext or ciphertext payloads;
- private keys, KEM secrets, signatures, or raw crypto material;
- authorization headers;
- request bodies;
- full client addresses.

Request IDs are generated locally and returned in X-Request-Id. They are
correlation identifiers, not authentication credentials.

## Health and readiness

- GET /health and GET /v1/health are liveness checks.
- GET /readyz and GET /v1/ready verify that the configured vault is available
  to the running server.
- GET /metrics exposes aggregate Prometheus metrics.

The readiness endpoint returns 503 Service Unavailable if the configured vault
is unavailable.

## CLI diagnostics

nexusq health performs a lightweight local check. With --vault PATH, it also
checks that the vault can be opened without unlocking it.

nexusq diagnostics --vault PATH reports non-secret format/KDF metadata and the
observability schema. It never unlocks the vault and never prints the password,
salt contents, key material, or vault contents.

## Configuration

The server continues to use RUST_LOG for structured log filtering, with a safe
nexusq_server=info default. No external telemetry service is required.

This phase does not deploy Prometheus, Grafana, OpenTelemetry, or a remote
collector. Those remain deployment/integration concerns rather than core
requirements.

## Validation

Phase 18 validation performed locally includes:

- cargo fmt --all;
- cargo check --workspace;
- cargo clippy --workspace --all-targets -- -D warnings;
- observability unit tests;
- CLI health/diagnostics parsing test;
- server metrics/request-id integration test;
- real nexusq health and nexusq diagnostics executions;
- review that test output contains no secret material.

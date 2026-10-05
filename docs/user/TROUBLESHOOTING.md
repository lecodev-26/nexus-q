# Troubleshooting

## The server refuses to start

Check:

1. `NEXUSQ_VAULT_PATH` is set and points to an existing vault.
2. `NEXUSQ_SERVER_TOKEN` is set and is at least 32 bytes.
3. Numeric settings are positive integers.
4. A non-loopback bind has `NEXUSQ_TRUSTED_TLS_TERMINATION=1`.
5. The service account can read the vault.

The server intentionally fails closed on invalid deployment configuration.

## Health is OK but readiness is not

`/health` reports process liveness. `/readyz` additionally checks that the configured vault path is available.

## Protected API returns 401

Send the configured bearer token:

```text
Authorization: Bearer <server-token>
```

Do not put the token into logs or source control.

## Protected API returns 423

The vault is locked. Unlock it through the authenticated `/v1/vault/unlock` endpoint.

## Metrics are empty or missing

Confirm that the request reached `/metrics` on the intended server instance. Metrics are process-local aggregate counters and do not include user-controlled labels.

## CLI password problems

Prefer interactive prompts. For automation, use `--password-file` and protect that file with restrictive permissions.

## RISC-V runtime

A successful cross-build only proves target compilation. It does not prove end-to-end runtime behavior on RISC-V hardware or an emulator.

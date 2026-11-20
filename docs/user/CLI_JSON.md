# CLI JSON Output

For the complete command list and options, see the [CLI Guide](CLI.md). The global `--output json` option prints command results as JSON; it does not change what the command does.

## Examples

These outputs were captured from the default RustCrypto build. Backend fields can differ when the binary is built with other Cargo features.

```bash
nexusq --output json health
```

```json
{
  "hardware_backend": "software",
  "native_pqc_backend_available": false,
  "observability_schema": 1,
  "pqc_backend": "rustcrypto",
  "pqc_backend_experimental": false,
  "status": "ok",
  "vault": "not_checked"
}
```

The health command is read-only. Without `--vault`, it reports `"vault": "not_checked"`; it does not unlock a vault.

```bash
nexusq --output json backend
```

```json
{
  "default_provider": "rustcrypto",
  "experimental": false,
  "name": "rustcrypto",
  "native_available": false,
  "selection": "compile-time Cargo feature"
}
```

## Handling errors in scripts

Check the process exit status before parsing output. Successful command results use stdout (unless `--quiet` suppresses them) and exit with code `0`. Command errors handled by the CLI use stderr and a nonzero exit code; their JSON object has a numeric `code` and an `error` message. For example, an I/O error has this shape (the message varies by platform and cause):

```json
{
  "code": 7,
  "error": "i/o error: <platform-specific message>"
}
```

Use the exit status to decide whether the command succeeded, then parse stdout on success or stderr on failure. The CLI error-code meanings are listed in [API Reference, section 6.3](../API.md#63-exit-codes).

Argument-parsing failures and Clap's built-in help and version responses are text, not JSON command results. Check the exit status before attempting to parse stderr as JSON.

JSON is an output format, not a security attestation, audit result, or certification. Do not put passwords, tokens, private keys, or other secret material in examples or logs. For scripted vault operations, use `--password-file` instead of a password argument and keep that file private.

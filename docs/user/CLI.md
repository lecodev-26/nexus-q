# CLI Guide

The `nexusq` CLI is a thin wrapper around `nexusq-core`. It contains no independent cryptography.

## Global options

- `--output human` — default human-readable output.
- `--output json` — machine-readable JSON.
- `--quiet` — suppress successful non-error output.

## Health and diagnostics

```bash
nexusq health
nexusq health --vault ./example.nqv
nexusq diagnostics
nexusq diagnostics --vault ./example.nqv
nexusq --output json health
nexusq version
```

Health and diagnostics do not unlock a vault.

## Vault

```text
nexusq vault create <path> [--label <label>] [--password-file <path>]
nexusq vault status <path>
nexusq vault attach-audit <vault> <audit-dir> [--password-file <path>]
```

## Keys

```text
nexusq key generate <vault> --algorithm <algorithm> --purpose <purpose>
nexusq key list <vault> [--password-file <path>]
nexusq key info <vault> <key-id> [--password-file <path>]
```

Current CLI algorithms are `ed25519`, `mlkem768`, `aes256gcm`, and `chacha20poly1305`.

Current purposes are `sign`, `encrypt`, `decrypt`, `key_agreement`, and `wrap`.

## Data

```text
nexusq data encrypt <vault> --key-id <key-id> [--metadata <text>] <input>
nexusq data decrypt <vault> <input.nqx> <output>
```

## Signatures

The CLI uses identities for signing:

```text
nexusq sign sign <vault> --identity <identity-id> <input>
nexusq sign verify <vault> --identity <identity-id> <input> <signature>
```

## Identities

```text
nexusq identity create <vault> [--label <label>]
nexusq identity list <vault>
```

## Credentials

```text
nexusq credential issue <vault> --issuer <id> --subject <id> --claims <json> <output>
nexusq credential verify <vault> <input>
```

## Audit

```text
nexusq audit verify <audit-dir> --vault <vault> [--password-file <path>] --vault <vault> [--password-file <path>]
nexusq audit show <audit-dir> [--last <n>]
```

## Password handling

Interactive password input is preferred. For automation, use `--password-file`. Do not pass passwords as command-line arguments.

The CLI does not intentionally print secret material.

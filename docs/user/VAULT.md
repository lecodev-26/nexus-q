# Vault Guide

A NEXUS-Q vault is encrypted persistent storage for key and identity material.

## Lifecycle

The normal lifecycle is:

1. Create a vault.
2. Unlock it for an operation.
3. Perform key, identity, encryption, or credential operations.
4. Lock/persist the session.

The CLI performs this lifecycle per command. The server keeps one vault object and an optional unlocked session in memory.

## Create

```bash
nexusq vault create ./example.nqv --label example
```

The password is requested interactively unless `--password-file` is supplied.

## Inspect

```bash
nexusq vault status ./example.nqv
nexusq health --vault ./example.nqv
nexusq diagnostics --vault ./example.nqv
```

Diagnostics reports format and KDF metadata without unlocking the vault.

## Audit

Attach an audit directory once:

```bash
nexusq vault attach-audit ./example.nqv ./audit
```

Then verify the chain:

```bash
nexusq audit verify ./audit
```

Audit records are tamper-evident and must not contain secret material.

## Backup and recovery

Back up the vault and its configured audit data together using the documented storage/recovery procedure. Protect backups as sensitive cryptographic material.

Do not copy vaults or password files into a Git repository.

See [Deployment](DEPLOYMENT.md) for operational backup/recovery guidance and [Storage](../STORAGE.md) for persistent formats.

# NexusQ administrative security (issue #70)

Historical note: this document describes local administrative primitives introduced during 4.1.1 work. It is not a claim that the release is production-certified or published.

## RBAC

`nexusq-admin::RbacStore` stores identity subjects, SHA-256 hashes of opaque bearer tokens, roles, tenant scopes, and enabled state. Plaintext bearer tokens are not persisted. Authentication uses a fixed-size digest comparison and short tokens are rejected. Permission checks are default-deny and tenant-scoped. Only a root identity can grant root/security-administrator roles; a non-root security administrator can grant only scopes it already holds. The last enabled root identity cannot be revoked. The initial root bootstrap is one-time and must be performed through a trusted provisioning path.

The HTTP integration in `nexusq-pki-cluster::router_with_admin` exposes tenant status and issuance-policy changes. These routes require a bearer token recognized by the RBAC store, explicit permission, tenant scope, and a healthy audit sink. The existing tenant-specific enrollment token remains separate; it is not implicitly elevated into an administrative identity.

## Encrypted snapshots

`export_encrypted_snapshot` validates the HA snapshot before encrypting it with XChaCha20-Poly1305. The key is derived from a caller-supplied passphrase using Argon2id (64 MiB, 3 iterations, one lane); salt and nonce are freshly generated for every backup and authenticated header bytes are used as AEAD associated data. Import checks the format, size limit, AEAD tag, tenant identity, and HA snapshot checksum/hash chain before returning data. Backup files are created atomically with owner-only permissions on Unix and are not overwritten.

The application must obtain passphrases from a secret manager or operator-controlled secret input. Never put passphrases in command-line arguments, URLs, audit events, logs, or source control. The primitives do not automatically copy backups off-host or implement a retention schedule; deployment orchestration must do that and test restores regularly.

## Audit log

`AuditLog` records structured events only; it intentionally has no arbitrary detail/message field. Each line includes a sequence, timestamp, actor, action, optional tenant/resource identifiers, outcome, previous hash, record hash, and HMAC-SHA-256 authentication. Opening a log verifies the entire chain before accepting writes. Appends are flushed with `sync_data`; a failed append poisons the writer so later writes cannot be appended behind a potentially partial record. On Unix the file is created or tightened to mode `0600`.

The HMAC key must be generated and retained by an external KMS/secret manager, independently of the log. The chain detects tampering only while the key remains secret; an administrator who can replace both the log and its key could forge a new chain. Production deployments should periodically anchor `head_hash()` in a separate protected system and ship audit records to remote append-only storage. Audit fields must never contain private keys, passphrases, bearer tokens, CSR bodies, or certificate private material.

## Operational caveats

- Backups are tenant-bound and import rejects a different tenant. A successful cryptographic import is not itself permission to restore; the caller must authorize `Permission::RestoreBackup` and audit the operation.
- Do not use a single shared token for tenant API access and administrative RBAC.
- Protect the RBAC database and audit key with filesystem/service-account isolation; the library does not replace OS access controls, MFA, or a secret manager.
- Before release, run the full workspace test suite, dependency/security review, backup restore drills, and API authorization tests against the deployment configuration.

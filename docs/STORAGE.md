# NEXUS-Q — Storage

> **Status:** Living reference document
> **Audience:** Contributors, integrators, security reviewers
> **Scope:** On-disk formats, atomicity, recovery, versioning and migration

---

## 1. Purpose

This document specifies **every persistent format that NEXUS-Q writes to
disk**, how those formats are protected, and how they evolve over time.
It is the authoritative reference for the `storage` module.

If a byte is written to disk by NEXUS-Q, it is described here. There are
no ad-hoc files, no temporary formats that escape this document.

---

## 2. General rules

Every persistent format in NEXUS-Q obeys these rules:

1. **Version byte first.** The first byte of every file is a format
   version identifier. Parsers reject unknown versions.
2. **Self-describing.** A file identifies its algorithm, structure, and
   version without external context.
3. **Authenticated.** All persistent data is authenticated with an AEAD
   tag or a MAC. Tampering is detectable.
4. **Atomic.** Writes are either fully applied or not applied at all.
   No partial states are visible to readers.
5. **Recoverable.** If a write is interrupted (power loss, kill -9), the
   file on disk is either the old version or the new version, never a
   corrupt hybrid.
6. **Migratable.** When a format changes, a documented migration path
   exists. Users never lose data because we changed our minds.
7. **Minimal surface.** We write as few distinct formats as possible.
   Every new format is a maintenance burden.

---

## 3. Format inventory

NEXUS-Q writes exactly **five** persistent formats:

| ID    | Format          | Purpose | File naming |
|-------|-----------------|---------|-------------|
| F-01  | Vault file      | Stores keys + metadata | `*.nqv` (NEXUS-Q Vault) |
| F-02  | Envelope        | Stores encrypted data + wrapped key | `*.nqx` (NEXUS-Q envelope) |
| F-03  | Storage DB      | Index and metadata (non-secret) | `*.nqs` (NEXUS-Q Storage) |
| F-04  | Audit log       | Chained audit events | `*.nqa` (NEXUS-Q Audit) |
| F-05  | Backup bundle   | Wrapped keys + metadata for backup | `*.nqb` (NEXUS-Q Backup) |

No other file format is written by NEXUS-Q. If a new format is needed, it
is added to this table with a new F-XX ID and a new version scheme.

---

## 4. The vault file (F-01)

The vault file is the root of a NEXUS-Q installation. It stores wrapped
keys and metadata, protected by a Key Encryption Key (KEK) derived from a
user credential.

### 4.1 Structure

```

+---------------------------------------------------------+

| Magic           | "NQV1" (4 bytes)                       |
+---------------------------------------------------------+

| Version         | 0x01 (1 byte)                          |
+---------------------------------------------------------+

| Flags           | bitfield (2 bytes, reserved)           |
+---------------------------------------------------------+

| KDF params      | Argon2id params (algorithm, mem, iter,  |

|                 | parallelism), variable length          |
+---------------------------------------------------------+

| Salt            | 16-32 bytes, unique per vault          |
+---------------------------------------------------------+

| KEK verifier    | HMAC-SHA256(KEK, "nexusq-kek-check")   |
+---------------------------------------------------------+

| Encrypted body  | AEAD-encrypted (AES-256-GCM) blob:     |

|                 |   - key records                        |

|                 |   - metadata records                   |

|                 |   - policy snapshots                   |
+---------------------------------------------------------+

| Body nonce      | 12 bytes                               |
+---------------------------------------------------------+

| Body tag        | 16 bytes (AEAD tag)                    |
+---------------------------------------------------------+

```

**Fields:**

- **Magic**: identifies the file as a NEXUS-Q vault.
- **Version**: format version. Currently `0x01`.
- **Flags**: reserved for future features (compression, multi-user, etc.).
- **KDF params**: required to derive the KEK from the password.
  Stored in cleartext because the attacker needs them anyway.
- **Salt**: unique per vault; used with Argon2id.
- **KEK verifier**: allows checking if a password is correct without
  decrypting the whole body (which could leak padding info via timing).
- **Encrypted body**: the actual vault content (keys, metadata).
- **Body nonce, tag**: AEAD parameters.

### 4.2 Associated data (AAD)

The AEAD AAD for the vault body is:

```

AAD = Magic || Version || Flags || KDF_params || Salt || KEK_verifier

```

This binds the header to the body: any modification of the header
invalidates the body's tag.

### 4.3 KEK derivation

```

KEK = Argon2id(
password,
salt,
memory      = 64 MiB,
iterations  = 3,
parallelism = 1,
output_len  = 32
)

```

Parameters are stored in the header and can be upgraded on re-encryption.

### 4.4 Body structure

The encrypted body is a serialized structure (format TBD, likely CBOR or
a custom length-prefixed binary format) containing:

```

VaultBody {
keys:      [KeyRecord],
metadata:  VaultMetadata,
policies:  [PolicySnapshot],
}

```

Each `KeyRecord` contains:

- KeyId
- Algorithm
- Purpose
- Status
- Wrapped key material (wrapped under the KEK)
- Metadata (see `KEY_MANAGEMENT.md` §4)

### 4.5 Atomic writes

Writing a vault file is done atomically:

1. Write the new vault to `vault.nqv.tmp`.
2. `fsync` the temp file.
3. `rename("vault.nqv.tmp", "vault.nqv")`.
4. `fsync` the containing directory.

`rename(2)` is atomic on POSIX. Readers always see either the old or the
new file, never a partial write.

### 4.6 Failure modes

| Failure                     | Result |
|-----------------------------|--------|
| Power loss mid-write        | Old vault intact; tmp file may be orphaned (cleaned on next open) |
| Disk full mid-write         | Write fails; old vault intact |
| Tampered vault file         | Detected on AEAD verification; refused |
| Wrong password              | Detected on KEK verifier; refused without full decrypt |
| Unknown format version      | Refused (fail-closed) |

---

## 5. The envelope (F-02)

An envelope is the format used to encrypt **user data** (files, messages,
records). It is self-contained: it carries everything needed to decrypt,
except the key.

### 5.1 Structure

```

+---------------------------------------------------------+

| Magic           | "NQX1" (4 bytes)                       |
+---------------------------------------------------------+

| Version         | 0x01 (1 byte)                          |
+---------------------------------------------------------+

| Flags           | bitfield (2 bytes, reserved)           |
+---------------------------------------------------------+

| Algorithm ID    | AEAD algorithm (2 bytes)               |
+---------------------------------------------------------+

| KeyId           | 16 bytes (the DEK's KeyId)             |
+---------------------------------------------------------+

| Nonce           | 12 bytes                               |
+---------------------------------------------------------+

| Wrapped DEK     | KEM ciphertext or AEAD-wrapped DEK     |
+---------------------------------------------------------+

| Metadata length | 4 bytes (uint32, big-endian)           |
+---------------------------------------------------------+

| Metadata        | variable-length, authenticated         |
+---------------------------------------------------------+

| Ciphertext      | AEAD-encrypted payload                 |
+---------------------------------------------------------+

| Tag             | 16 bytes (AEAD tag)                    |
+---------------------------------------------------------+

```

**Fields:**

- **Magic, Version, Flags**: as with the vault.
- **Algorithm ID**: identifies the AEAD used (AES-256-GCM, ChaCha20-Poly1305).
- **KeyId**: identifies the DEK used. Bound into AAD.
- **Nonce**: unique per encryption. Never reused with the same DEK.
- **Wrapped DEK**: the DEK, wrapped under the recipient's KEK or KEM key.
  For envelope to a public key: KEM ciphertext (ML-KEM hybrid). For
  envelope to the vault: AEAD-wrapped.
- **Metadata**: user-provided or system-provided associated metadata.
  Authenticated (part of AAD) but not encrypted.
- **Ciphertext**: the encrypted payload.
- **Tag**: AEAD authentication tag.

### 5.2 AAD

```

AAD = Magic || Version || Flags || AlgorithmID || KeyId || Nonce || Metadata

```

This binds all header fields to the ciphertext. Changing any field
invalidates the tag.

### 5.3 Metadata

Envelope metadata is application-defined but follows these rules:

- Serialized canonically (deterministic bytes).
- Authenticated (in AAD).
- Small (recommended max: 64 KiB).
- Never contains secrets.

Examples: original filename, MIME type, creation timestamp, signer
identity, purpose tag.

### 5.4 File naming convention

Encrypted files use the extension `.nqx`:

- `document.pdf` → `document.pdf.nqx`
- `backup.tar` → `backup.tar.nqx`

This makes encrypted files distinguishable without opening them.

### 5.5 Corruption detection

On decrypt:

1. Verify magic and version.
2. Verify AAD is consistent with ciphertext.
3. Verify AEAD tag.

If any of these fail, the operation is refused. **No partial plaintext is
ever returned**, even if only the last byte was tampered with.

---

## 6. Storage DB (F-03)

The storage DB is an **index** and **metadata store** for the vault. It
does **not** contain secret material; it contains pointers, timestamps,
and structural information.

### 6.1 Purpose

- Fast lookup of keys by KeyId.
- List of envelopes, their metadata, and their status.
- Index for audit log segments.
- Configuration snapshots.

### 6.2 Structure

The storage DB is a **versioned, checksummed log** of records:

```

+---------------------------------------------------------+

| Magic           | "NQS1" (4 bytes)                       |
+---------------------------------------------------------+

| Version         | 0x01 (1 byte)                          |
+---------------------------------------------------------+

| Record count    | 8 bytes (uint64, big-endian)           |
+---------------------------------------------------------+

| Record[0]       | length-prefixed record                 |
+---------------------------------------------------------+

| Record[1]       | length-prefixed record                 |
+---------------------------------------------------------+

| ...             | ...                                    |
+---------------------------------------------------------+

| Trailer CRC     | 4 bytes (CRC32C over all records)      |
+---------------------------------------------------------+

```

Each record:

```

Record {
kind:     uint8   (KEY_INDEX, ENVELOPE_INDEX, CONFIG, ...),
key:      bytes   (lookup key, e.g., KeyId),
value:    bytes   (serialized metadata),
crc:      uint32  (CRC32C over kind || key || value),
}

```

### 6.3 Not encrypted, but authenticated

The storage DB is **not** encrypted because it contains no secrets. It
**is** integrity-protected (CRC + optional MAC) to detect accidental or
malicious modification.

If metadata itself is sensitive (e.g., filenames), the value field is
itself an encrypted blob (AEAD) using the vault KEK.

### 6.4 Compaction

Append-only logs grow. Compaction rewrites the log with only the current
state:

1. Read all records, resolve to final state.
2. Write new log to `.nqs.tmp`.
3. `fsync`.
4. Atomic rename.
5. `fsync` directory.

Compaction is triggered by size or age, at the application's discretion.

### 6.5 Concurrent access

The storage DB is single-writer. If multiple NEXUS-Q processes need to
access the same vault, they coordinate via:

- A **lock file** (`vault.nqv.lock`) with `flock(2)`.
- Or a dedicated NEXUS-Q server process (Fase 14).

Multiple readers are allowed only in a snapshot-consistent mode (read a
frozen copy). Concurrent writers are never allowed.

---

## 7. Audit log (F-04)

The audit log stores the chained events described in `SECURITY_MODEL.md`
§7.

### 7.1 Structure

```

+---------------------------------------------------------+

| Magic           | "NQA2" (4 bytes)                       |
+---------------------------------------------------------+

| Version         | 0x01 (1 byte)                          |
+---------------------------------------------------------+

| Segment ID      | 16 bytes (random, per segment)         |
+---------------------------------------------------------+

| Prev segment    | 32 bytes (hash of previous segment's  |

|                 | trailer, or zeros for the first)       |
+---------------------------------------------------------+

| Event[0]        | length-prefixed event record           |
+---------------------------------------------------------+

| Event[1]        | length-prefixed event record           |
+---------------------------------------------------------+

| ...             | ...                                    |
+---------------------------------------------------------+

| Segment hash    | 32 bytes (chain hash over all events   |

|                 | in this segment + prev_segment)        |
+---------------------------------------------------------+

```

Each event matches the structure in `SECURITY_MODEL.md` §7.1.

### 7.2 Segments

The audit log is **segmented**: each segment is a file
(`audit-00001.nqa`, `audit-00002.nqa`, ...). Segments chain to the
previous segment via `prev_segment`.

Segmentation allows:

- Bounded file sizes.
- Retention: old segments can be archived or removed (breaking the chain
  before that point is documented and detectable).
- Parallel verification of segments.

### 7.3 Append-only, fsync per event

Every audit event is `fsync`'d before the operation is considered
successful. If the audit write fails, the operation **fails** (see
`SECURITY_MODEL.md` §7.6).

### 7.4 Verification

Verification tools (Fase 12, CLI) can:

- Verify one segment.
- Verify the whole chain from the first segment.
- Detect truncation (via `prev_segment` mismatch).

### 7.5 Usage in code

The audit log is exposed through the `storage` module. The typical
flow inside a deployment is:

```rust
use nexusq_core::storage::AuditLog;
use nexusq_core::vault::Vault;

// 1. Open or create the vault.
let vault = Vault::open("vault.nqv")?;

// 2. Unlock to get a session.
let mut session = vault.unlock(password)?;

// 3. Attach an audit log living next to the vault.
session.enable_audit("audit/")?;

// 4. Perform operations. Auditable security operations append an
//    event and persists the segment before returning.
let key_id = session.generate_key(algorithm, purpose)?;
session.activate_key(&key_id)?;

// 5. On shutdown, lock the session. The audit log is already on
//    disk; no explicit flush is needed.
session.lock()?;
```

The directory passed to enable_audit must exist. The first call
creates audit-00001.nqa inside it; later sessions continue from
the highest-numbered segment.

Failure to log means failure to operate. If a segment cannot be
written (disk full, permissions revoked), the operation returns an
error and the caller must treat it as failed. The session is not
left in a half-audited state: the mutation that already happened
stays in memory, but the caller knows the log did not record it and
can decide how to proceed. This is documented behavior, not a
rollback.

Verification. To verify the log independently, open it again and
call verify_all:

```rust
session.verify_audit()?;
log.verify_all()?;
```

verify_all walks every segment in numeric order, checks each
segment's internal chain (index monotonicity, prev_hash linkage,
per-event hash), and confirms that each segment's prev_segment
matches its predecessor's segment_hash. Any mismatch is a tamper
indication.

Rotation. Segments rotate automatically at max_events (default
1000). The rotation is transparent: appending past the threshold
finalizes the current segment and starts a new one whose
prev_segment is the hash of the closed segment.

### 7.6 What is never logged

The rules from SECURITY_MODEL.md §7.4 apply at the storage layer
too:

· Private keys or any key material.
· Plaintext of user data.
· Passwords or password-derived material.
· Full ciphertexts (only hashes or identifiers).

An event carries the actor, the subject (typically a KeyId or an
IdentityId), the outcome, and a small opaque context blob that the
application controls. The core library never fills context with
data that could be sensitive.
---

## 8. Backup bundle (F-05)

A backup bundle is a self-contained, portable archive of vault contents.
It is used for **disaster recovery** and **portability**.

### 8.1 Structure

```

+---------------------------------------------------------+

| Magic           | "NQB1" (4 bytes)                       |
+---------------------------------------------------------+

| Version         | 0x01 (1 byte)                          |
+---------------------------------------------------------+

| KDF params      | Argon2id params (see vault)            |
+---------------------------------------------------------+

| Salt            | 16-32 bytes, unique per backup         |
+---------------------------------------------------------+

| KEK verifier    | HMAC-SHA256(backup_KEK, "nexusq-backup-kek") |
+---------------------------------------------------------+

| Encrypted body  | AEAD-encrypted (AES-256-GCM) blob:     |

|                 |   - key records (including private!)   |

|                 |   - metadata                           |

|                 |   - optional audit snapshot            |
+---------------------------------------------------------+

| Body nonce      | 12 bytes                               |
+---------------------------------------------------------+

| Body tag        | 16 bytes (AEAD tag)                    |
+---------------------------------------------------------+

```

### 8.2 Backup passphrase

The backup KEK is derived from a **separate** passphrase, not the vault
password. Rationale: a compromised vault password should not
automatically compromise backups, and vice versa.

Recommended: use a strong passphrase (diceware, 6+ words) or a printed
recovery phrase.

### 8.3 Contents

A full backup contains:

- All key records (including private material, wrapped under the backup KEK).
- All metadata.
- Optionally, a copy of the audit log up to a certain segment.

### 8.4 Restore

Restore creates a **new vault** from the backup:

1. Prompt for backup passphrase.
2. Derive backup KEK.
3. Verify integrity (KEK verifier + AEAD tag).
4. Create new vault (new salt, new vault password).
5. Re-wrap all keys under the new vault KEK.
6. Write audit event `VAULT_RESTORED`.

Restore is explicit; there is no automatic restore on startup.

### 8.5 Backup is not sync

A backup is a **point-in-time** snapshot. It is not a synchronization
mechanism. There is no "restore the latest" — the user picks a specific
backup file.

---

## 9. Atomic writes (recap)

All five formats use the same atomic-write pattern:

1. Write to `<name>.tmp` in the same directory.
2. `fsync` the temp file.
3. `rename` to the final name.
4. `fsync` the containing directory.

This guarantees that a reader always sees a consistent file, and that a
crash leaves the filesystem in a recoverable state.

### 9.1 Orphan temp files

If a crash occurs between steps 1 and 3, a `<name>.tmp` file remains. On
next open of the containing directory, NEXUS-Q:

- Ignores temp files that are not referenced.
- Optionally, deletes them after a grace period.

Temp files are never read as if they were final files.

### 9.2 Directory fsync

On POSIX, `rename` is atomic but the directory entry may not be persisted
across a crash without `fsync` on the directory. NEXUS-Q always `fsync`s
the containing directory after a rename for security-relevant files.

---

## 10. Versioning and migration

Every format has a version byte. When a format changes incompatibly, the
version is bumped, and a migration path is documented here.

### 10.1 Rules for version bumps

- **Patch changes** (bug fixes, clarifications) do not bump the version.
- **Compatible additions** (new optional fields that older readers can
  ignore) may bump a "minor" version, but old readers must still work.
- **Incompatible changes** (new required fields, changed semantics) bump
  the major version and require migration.

### 10.2 Migration procedure

When opening a file with an old version:

1. Detect version.
2. If the version is **newer** than we support: refuse (fail-closed).
3. If the version is **current**: proceed normally.
4. If the version is **older**:
   - If a migration path exists: offer to migrate (or migrate
     automatically, per policy).
   - If no migration path exists: refuse, with a clear error.

### 10.3 Migration is atomic

Migration is done via the same atomic-write pattern:

1. Read old file, validate.
2. Write new file to `<name>.migrating`.
3. `fsync`.
4. Rename `<name>` to `<name>.bak.<timestamp>`.
5. Rename `<name>.migrating` to `<name>`.
6. `fsync` directory.

If anything fails, the old file is intact (either still in place or in
`.bak`), and the operation can be retried.

### 10.4 Migration log

Every migration writes an audit event:

```

MIGRATION_PERFORMED
file:        path
from_version: X
to_version:   Y
timestamp:    ...

```

### 10.5 Forward compatibility

We do **not** aim for forward compatibility (old NEXUS-Q reading new
files). We aim for **backward compatibility** (new NEXUS-Q reading old
files, via migration). This is the industry norm for security software:
the cost of forward compatibility is usually worse than the cost of an
upgrade.

### 10.6 Downgrade

Downgrading NEXUS-Q after a migration is **not** supported. Users who
need to downgrade must restore from a backup made before the migration.

---

## 11. Corruption and recovery

### 11.1 Sources of corruption

- Bit rot (silent disk errors).
- Power loss during write (handled by atomic writes).
- Malicious modification (handled by AEAD / MAC / CRC).
- Software bugs (handled by versioning + tests + fuzzing).

### 11.2 Detection

Each format detects corruption in its own way:

| Format | Detection |
|--------|-----------|
| Vault (F-01) | AEAD tag over body; KEK verifier; magic/version |
| Envelope (F-02) | AEAD tag; AAD consistency; magic/version |
| Storage DB (F-03) | CRC32C per record; overall trailer CRC |
| Audit log (F-04) | Per-event hash; segment hash; prev_segment link |
| Backup (F-05) | AEAD tag; KEK verifier; magic/version |

### 11.3 Response to corruption

- **Vault corrupted**: refuse to open; suggest restore from backup.
- **Envelope corrupted**: refuse to decrypt; the data is lost unless a
  good copy exists.
- **Storage DB corrupted**: refuse to open; attempt repair from
  redundancy (if available) or rebuild index from vault + envelopes.
- **Audit log corrupted**: verification fails; the log is flagged as
  tampered. Operations may continue but with warnings.
- **Backup corrupted**: refuse to restore; the backup is unusable.

### 11.4 No silent repair

NEXUS-Q never silently repairs a corrupted file. If repair is possible,
it is done explicitly, with a new file, and logged. The corrupted
original is preserved (renamed `.corrupt.<timestamp>`) for forensics.

---

## 12. Platform-specific considerations

### 12.1 Filesystem support

NEXUS-Q requires:

- POSIX `rename(2)` semantics (atomic rename within a directory).
- `fsync(2)` on files and directories.
- File permissions (mode bits) enforced by the OS.

On Android / Termux: these are provided by the Linux kernel, accessible
via standard syscalls. `~/storage/shared/` (shared storage) may **not**
provide all guarantees (FUSE-based, slower, may not support `flock`).
**Recommendation:** keep the vault in Termux's private storage
(`$HOME`), not in shared storage.

### 12.2 SSD and flash storage

On SSDs and flash (including Android internal storage):

- **Overwrite is not guaranteed.** Writing to a sector may leave the
  previous data readable at the physical level.
- **TRIM** may or may not be available.
- **Wear leveling** spreads writes, making "overwrite" unreliable.

Implication: **key destruction on flash storage is best-effort**. Full
erasure requires full-disk encryption with a discardable key (a
platform feature), or physical destruction.

We document this limitation; we do not pretend otherwise.

### 12.3 Cloud-synced folders

**Do not** store the vault in Dropbox, Google Drive, OneDrive, or any
cloud-synced folder. Cloud sync may:

- Leak the vault file to the cloud provider.
- Cause partial writes that are not atomic across devices.
- Create conflicts that break the atomic-write model.

This is documented but not enforced (the user can put the vault
anywhere). The README warns against it.

### 12.4 Network filesystems

NFS, SMB, and similar filesystems may not provide atomic `rename` or
reliable `fsync`. NEXUS-Q detects unsupported filesystems where possible
and refuses to operate, but detection is imperfect. Documented
limitation.

### 12.5 File permissions

NEXUS-Q creates vault files with mode `0600` (owner read/write only) by
default. On multi-user systems, this is enforced by the OS. On single-user
systems (Android), the isolation is provided by the OS's app sandbox.

---

## 13. Reserved extensions

To make future evolution smoother, NEXUS-Q reserves:

- `*.nqv`, `*.nqx`, `*.nqs`, `*.nqa`, `*.nqb` — NEXUS-Q native formats.
- `*.nqv.tmp`, `*.nqx.tmp`, etc. — temp files during atomic write.
- `*.nqv.bak.<timestamp>` — backups during migration.
- `*.nqv.corrupt.<timestamp>` — preserved corrupt files.

Users and downstream tools should **not** create files with these
extensions unless they are NEXUS-Q itself.

---

## 14. Threat-model alignment

This document implements defenses for the following threats from
`THREAT_MODEL.md`:

- **T-01 (ciphertext tampering)**: AEAD tag on every format.
- **T-03 (replay of old ciphertext)**: envelope versioning +
  anti-rollback at the storage DB level.
- **T-06 (vault theft)**: vault encrypted under Argon2id-derived KEK.
- **T-07 (malicious vault file)**: strict parsing, fuzzing (Fase 15).
- **T-09 (audit log tampering)**: vault-derived HMAC-SHA256 authentication across events and segments.
- **T-10 (silent downgrade)**: version byte, no fallback for unknown
  versions.
- **T-12 (cross-version format confusion)**: magic + version per format.

Threats that storage cannot mitigate:

- **O-03 (cold boot)**: storage is at rest; RAM is a different surface.
- **O-04 (side channels)**: not a storage concern.
- **O-10 (zero-day in OS/filesystem)**: out of scope.

---

## 15. Open questions

- [ ] Serialization format for vault body: CBOR, custom binary, MessagePack?
- [ ] Whether to use SQLite for storage DB or a custom log
- [ ] Segment size for audit log (events per segment, or bytes)
- [ ] Compression: per-envelope, and if so, which (zstd? none by default)
- [ ] Multi-user vault support in v1.0 or v1.1
- [ ] Encryption of storage DB metadata vs. only integrity

Resolved in Fase 4 (Vault), Fase 10 (Storage).

---

## 16. References

- `docs/ARCHITECTURE.md` — storage module
- `docs/CRYPTOGRAPHY.md` — AEAD, KDF, hash used here
- `docs/KEY_MANAGEMENT.md` — what is stored in vault and envelopes
- `docs/SECURITY_MODEL.md` — audit chain format and verification
- `docs/THREAT_MODEL.md` — threats this document defends against
- POSIX.1-2017 — `rename(2)`, `fsync(2)`, file permissions
- NIST SP 800-38D — AEAD construction
- RFC 9106 — Argon2
- RFC 8949 — CBOR (if used)

---

*End of document.*

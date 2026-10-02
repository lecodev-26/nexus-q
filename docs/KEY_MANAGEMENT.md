# NEXUS-Q — Key Management

> **Status:** Draft (Fase 0)
> **Audience:** Contributors, security reviewers, integrators
> **Scope:** Key types, lifecycle, metadata, rotation, revocation, destruction

---

## 1. Purpose

This document defines **how NEXUS-Q manages cryptographic keys over their
entire lifetime**: from generation, through use, to rotation and eventual
destruction. It is the authoritative reference for the `vault` module and
for anyone implementing key-related features.

Cryptography protects data; key management protects the keys. If key
management is broken, cryptography is decorative.

---

## 2. Key types

NEXUS-Q manages five distinct types of keys. Each type has a specific
purpose and its own handling rules.

| Type             | Purpose                                | Lifetime        | Where it lives |
|------------------|----------------------------------------|-----------------|----------------|
| Master Key (MK)  | Root of a vault; derives subkeys       | Long (years)    | Vault (wrapped) |
| Key Encryption Key (KEK) | Wraps Data Encryption Keys    | Medium          | Derived from MK or password |
| Data Encryption Key (DEK) | Encrypts a single envelope   | Short (per-envelope) | Wrapped by KEK, never stored plain |
| Identity Key (IK) | Signs, verifies, authenticates        | Long            | Vault or hardware |
| Session Key (SK) | Protects an ephemeral session          | Very short (per-session) | Memory only |

### 2.1 Master Key (MK)

- One per vault.
- Never leaves the vault in plaintext.
- Used only to derive other keys, never to encrypt user data directly.
- Rotated only via a full vault re-key operation.

### 2.2 Key Encryption Key (KEK)

- Derived from the MK (or from a user password via Argon2id).
- Wraps and unwraps DEKs.
- There may be multiple KEKs per vault (e.g., one per user credential,
  so that adding/removing a user does not require re-encrypting all data).

### 2.3 Data Encryption Key (DEK)

- Generated randomly, one per envelope (file, message, record).
- Never stored in plaintext. Always wrapped by a KEK.
- Destroyed from memory as soon as encryption/decryption finishes.

### 2.4 Identity Key (IK)

- Represents a cryptographic identity.
- Used for signing, verification, authentication.
- May be split into **signing key** and **key agreement key** (see
  `ARCHITECTURE.md` §4.3).
- Public part may be exported freely; private part never leaves its
  storage (vault or hardware).

### 2.5 Session Key (SK)

- Established via KEM (ML-KEM + X25519 hybrid).
- Never persisted.
- Zeroized when the session ends.

---

## 3. Key identifiers (KeyId)

Every key in NEXUS-Q has a **KeyId**: a stable, unique, public identifier.

### 3.1 Format

```

nqk_<algorithm_prefix>_<base32-random>

```

Examples:

- `nqk_mlkem768_7f3a9c2e4d1b8a6f5e0c3d9b2a1f4e7c`
- `nqk_mldsa65_1a2b3c4d5e6f708192a3b4c5d6e7f809`
- `nqk_aes256gcm_abcdef0123456789abcdef0123456789`

**Rules:**

- Prefix `nqk_` = "NEXUS-Q key"
- Algorithm prefix identifies the primitive family at a glance
- Random part: 128 bits (32 hex chars), from CSPRNG
- Total length: fixed per algorithm family, no variable-length IDs
- Case-sensitive, lowercase only

### 3.2 Properties

- **Unique:** collision probability with 128-bit random is negligible
- **Opaque:** the ID reveals the algorithm but not the key material
- **Stable:** the ID never changes, even across rotation (the new key
  gets a new ID; the old one is marked revoked)
- **Non-secret:** safe to log, display, transmit

### 3.3 What a KeyId is NOT

- It is **not** a fingerprint of the key material (we do not derive the
  ID from the key; it is random).
- It is **not** an authorization token (knowing a KeyId grants nothing).
- It is **not** stable across vault copies if keys are re-generated (but
  it is stable when keys are exported/imported).

---

## 4. Key metadata

Every key has associated metadata. Metadata is stored in the vault, is
**not secret**, and is authenticated.

| Field             | Type       | Description |
|-------------------|------------|-------------|
| `key_id`          | KeyId      | The key's identifier |
| `algorithm`       | AlgId      | e.g., `ml-kem-768@v1` |
| `purpose`         | Purpose    | One of: SIGN, ENCRYPT, DECRYPT, KEY_AGREEMENT, WRAP |
| `created_at`      | Timestamp  | UTC, when the key was created |
| `created_by`      | String     | Identity or process that created it |
| `created_from`    | Origin     | `generated`, `imported`, `derived` |
| `status`          | Status     | See §5 |
| `version`         | Integer    | Rotation generation (starts at 1) |
| `owner`           | IdentityId | Identity responsible for this key |
| `rotation_due`    | Timestamp? | Optional policy-driven deadline |
| `expires_at`      | Timestamp? | Optional hard expiration |
| `parent_key_id`   | KeyId?     | For derived keys, the source |
| `hardware_backed` | Bool       | Whether the private part is in hardware |
| `attestation`     | Bytes?     | Optional attestation evidence |

### 4.1 Rules

- Metadata is **always** authenticated (via AEAD AAD or a MAC).
- Metadata is **never** secret (assume an attacker can read it if they
  have disk access).
- Metadata is **not** the authority on a key's use; the policy engine
  (see `SECURITY_MODEL.md`) has the final say.

---

## 5. Key lifecycle

A key moves through a well-defined state machine. Illegal transitions are
rejected.

```

```

### 5.1 States

| State       | Meaning | Allowed operations |
|-------------|---------|---------------------|
| GENERATED   | Just created, not yet in use | Activate, destroy |
| ACTIVE      | Normal operating state | Use (per purpose), rotate, revoke, export public |
| ROTATING    | Being replaced; grace period | Verify/decrypt (not sign/encrypt new data), finalize rotation |
| RETIRED     | Superseded by a newer key | Verify/decrypt only (for old data) |
| REVOKED     | Compromised or no longer trusted | None (verify only if explicitly allowed for forensics) |
| DESTROYED   | Key material erased | None. Metadata remains for audit. |

### 5.2 Transitions

- GENERATED → ACTIVE: on first use or explicit activation
- ACTIVE → ROTATING: when rotation is initiated
- ROTATING → RETIRED: when rotation completes
- ACTIVE → REVOKED: on suspected compromise
- RETIRED → REVOKED: on retroactive compromise discovery
- REVOKED → DESTROYED: on explicit destruction
- Any state → DESTROYED: **only** with a valid destruction policy

**Forbidden transitions:**

- DESTROYED → anything (destruction is final)
- REVOKED → ACTIVE (no resurrection)
- RETIRED → ACTIVE (no un-rotation)

### 5.3 Invariants

- A key in DESTROYED state has no key material anywhere (memory, disk,
  hardware). Only metadata remains.
- A key in REVOKED state is never used for new operations.
- A key in RETIRED state is never used for new encryptions or signatures,
  only for verification and decryption of data that was protected while
  it was ACTIVE.

---

## 6. Key generation

### 6.1 Rules

- Keys are generated only from a `RandomSource` (see `CRYPTOGRAPHY.md` §4.1).
- Minimum entropy: 256 bits for symmetric keys, and the algorithm-defined
  entropy for asymmetric keys.
- Generation is atomic: either the key exists (fully written) or it does
  not. No partial keys.
- The `KeyId` is generated **before** the key material, so the metadata
  record can be written first if needed.

### 6.2 Algorithms per purpose

| Purpose         | Allowed algorithms |
|-----------------|--------------------|
| SIGN            | ML-DSA-65, ML-DSA-87, SLH-DSA-*, Ed25519 (legacy) |
| ENCRYPT         | AES-256-GCM, ChaCha20-Poly1305 |
| DECRYPT         | AES-256-GCM, ChaCha20-Poly1305 |
| KEY_AGREEMENT   | ML-KEM-768 (+X25519 hybrid), ML-KEM-1024 |
| WRAP            | AES-256-GCM (key wrap mode) |

A key created for one purpose **cannot** be used for another. The vault
enforces this; the policy engine enforces it further.

### 6.3 Hardware-backed keys

When a hardware backend (TPM, Secure Element, HSM) is available and the
policy requires it:

- The private part is generated **inside** the hardware.
- It never leaves the hardware in plaintext.
- All operations (sign, decrypt, unwrap) are performed **inside** the
  hardware.
- The vault stores only a handle (reference), not the key material.

---

## 7. Rotation

### 7.1 Why rotate

- Limit the blast radius if a key is compromised.
- Comply with policies (e.g., "signing keys rotate yearly").
- Recover from suspected but unconfirmed compromise.

### 7.2 Rotation procedure

Rotating a key `K_old` to `K_new`:

1. Generate `K_new` with the same algorithm and purpose as `K_old`.
2. Mark `K_old` as **ROTATING**.
3. Re-encrypt or re-sign **only** the data that needs the active key:
   - Signing keys: nothing is re-signed (old signatures remain valid
     under `K_old`). New signatures use `K_new`.
   - Encryption keys: **nothing is re-encrypted immediately**. Instead,
     new envelopes are encrypted with `K_new`; old envelopes remain
     readable with `K_old` until an explicit migration.
4. Mark `K_old` as **RETIRED**.
5. New operations use `K_new`.

### 7.3 Grace period

A rotating key remains usable for **verification and decryption** until
explicit migration. There is no fixed grace period; the user or policy
decides when to retire fully.

### 7.4 Automatic rotation

Optional, policy-driven. If a rotation policy exists (e.g., "rotate
annually"), the vault schedules rotation and warns when due.

Automatic rotation **never** destroys old key material. It only marks it
RETIRED.

---

## 8. Revocation

### 8.1 When to revoke

- Suspected or confirmed compromise.
- Key no longer needed.
- Owner left the organization.

### 8.2 Revocation procedure

1. Mark the key **REVOKED** with a timestamp and reason.
2. Add a revocation record to the audit log.
3. New operations with this key fail (fail-closed).
4. Data previously protected by the key remains protected (the key
   material is still present, so old data is still readable if the
   policy allows).
5. Eventually, the key may be destroyed.

### 8.3 Revocation is not deletion

Revocation marks a key as "no longer trusted for new operations". It
does **not** delete the key material, because that would make old data
unrecoverable.

Destruction (§9) is the operation that deletes key material.

### 8.4 Distinction: REVOKED vs DESTROYED

| Aspect           | REVOKED | DESTROYED |
|------------------|---------|-----------|
| Key material     | Still present | Erased |
| New operations   | Denied  | Denied |
| Old data decryptable | Yes (policy-dependent) | No (permanently) |
| Reversible       | No (no un-revoke) | No |
| Audit record     | Yes     | Yes (metadata only) |

---

## 9. Destruction

### 9.1 When to destroy

- Key was REVOKED and all data protected by it is either migrated or
  intentionally lost.
- Key was GENERATED but never used and is no longer needed.
- Compliance requires it (e.g., "right to be forgotten").

### 9.2 Destruction procedure

1. Verify the key is not the last KEK protecting any needed DEK.
2. Verify that any data encrypted under the key is either migrated or
   explicitly abandoned (requires user confirmation).
3. Overwrite key material in memory (zeroization).
4. Overwrite key material on disk (best-effort; SSDs may retain data —
   documented limitation).
5. If hardware-backed: send destroy command to the hardware.
6. Mark the key **DESTROYED** in metadata.
7. Write an audit event.

### 9.3 Irreversibility

Destruction is **final**. There is no "undo". The metadata record remains
so that future audits can see that the key existed and was destroyed.

### 9.4 Data loss warning

Destroying a key makes all data protected by it **permanently
unreadable**. The CLI and API must require explicit confirmation
(typing the KeyId, or an equivalent confirmation) before destroying a
key that protects any data.

---

## 10. Export and import

### 10.1 Public keys

Public keys may be exported freely. Formats:

- **NEXUS-Q native format** (versioned, self-describing)
- **Standard formats** where applicable (e.g., PEM for interop with
  legacy systems)

### 10.2 Private keys

Private keys are **never** exported in plaintext by default.

Allowed export modes:

- **Wrapped export**: the key is exported wrapped under a user-provided
  passphrase (Argon2id + AEAD). Used for backups.
- **Hardware export**: if the hardware allows a wrapped export (some HSMs
  do), the export is hardware-wrapped.
- **Shamir split**: the key is split into N shares, K of which are
  required to reconstruct. Shares are exported separately.

**Forbidden:** plaintext export of private keys, export without explicit
user confirmation, export to a non-secure channel.

### 10.3 Import

Imported keys follow the same rules as generated keys:

- Metadata is created with `created_from = "imported"`.
- The key starts in **GENERATED** state, must be explicitly activated.
- Import from a foreign format requires explicit algorithm mapping.
- Unknown algorithms are rejected (fail-closed).

### 10.4 Import of legacy keys

NEXUS-Q may import keys from legacy systems (Ed25519, P-256, etc.) for
transition purposes. Imported legacy keys:

- Are marked `legacy = true` in metadata.
- Can be used for **verification** and **decryption** of legacy data.
- **Cannot** be used for new signatures or new encryptions.
- Should be rotated to a PQC key at the earliest opportunity.

---

## 11. Backup and recovery

### 11.1 The problem

Keys protect data. If keys are lost, data is lost. But if keys are
copied carelessly, they leak. Backup is therefore one of the most
sensitive operations in NEXUS-Q.

### 11.2 Backup principles

1. **Never** back up keys in plaintext.
2. Backups are **wrapped** under a strong passphrase (Argon2id + AEAD).
3. Backup files carry the same versioning as any other NEXUS-Q format.
4. Backup files must be **self-verifying** (integrity check on restore).
5. Recovery requires explicit user action; there is no silent recovery.

### 11.3 Backup formats

- **Full vault backup**: all keys + metadata, wrapped under a passphrase.
- **Per-key backup**: a single key + its metadata, wrapped.
- **Recovery phrase**: for long-term vault keys, a mnemonic (BIP-39 style
  or equivalent) that can reconstruct the MK.

### 11.4 Recovery procedure

1. User provides the recovery phrase or passphrase.
2. NEXUS-Q verifies integrity of the backup file.
3. Keys are restored into a fresh vault.
4. Metadata is restored alongside.
5. An audit event is written.

### 11.5 What we do NOT do

- We do not store backups in the cloud by default.
- We do not escrow keys (no "recovery by support team").
- We do not transmit keys over the network for backup purposes (the
  user moves files manually).
- We do not silently rotate keys during recovery.

### 11.6 Lost key = lost data

If the user loses all copies of a key and has no recovery phrase, the
data protected by that key is **permanently lost**. This is a design
choice, not a bug.

---

## 12. Key custody

"Who holds the keys?" is a policy question, not just a technical one.
NEXUS-Q supports several custody models.

### 12.1 Self-custody

- The user holds the keys directly.
- The vault is on the user's device.
- Recovery is the user's responsibility.
- **Default for v1.0.**

### 12.2 Hardware-backed custody

- The key material lives in a TPM / Secure Element / HSM.
- The user has a handle but not the raw bytes.
- Recovery requires hardware-specific procedures (wrapped export, etc.).

### 12.3 Shared custody (Shamir)

- The key is split into N shares with threshold K.
- Any K of N shares reconstruct the key.
- Used for high-value keys in organizational settings.
- **Planned for v1.2**, not v1.0.

### 12.4 Distributed custody

- Multiple parties must cooperate to use a key (MPC, threshold signatures).
- **Out of scope for v1.0.** Future work.

### 12.5 Escrow

- A third party holds a copy of the key for recovery purposes.
- **Explicitly NOT supported.** Escrow weakens security and creates a
  single point of failure. Users who need escrow can implement it
  externally by wrapping a key under a share held by the third party.

---

## 13. Audit events for key operations

Every key operation emits an audit event. The following events are
mandatory:

| Event                | Trigger |
|----------------------|---------|
| `KEY_GENERATED`      | New key created |
| `KEY_IMPORTED`       | Key imported from external source |
| `KEY_ACTIVATED`      | Key moved to ACTIVE state |
| `KEY_USED`           | Key used for a crypto operation (SIGN, DECRYPT, ...) |
| `KEY_ROTATION_STARTED` | Rotation initiated |
| `KEY_ROTATION_COMPLETED` | Rotation finished |
| `KEY_RETIRED`        | Key moved to RETIRED |
| `KEY_REVOKED`        | Key moved to REVOKED, with reason |
| `KEY_DESTROYED`      | Key material erased |
| `KEY_EXPORTED`       | Key exported (wrapped) |
| `KEY_ACCESS_DENIED`  | Operation refused by policy |

Rules:

- Audit events **never** contain key material.
- Audit events **never** contain plaintext.
- Audit events **may** contain the KeyId, the operation, the caller
  identity, the timestamp, and the result.
- Audit events are chained (§`SECURITY_MODEL.md`) so that tampering is
  detectable.

---

## 14. Key management in hardware

When a hardware backend is used:

- The vault stores only a **handle** (opaque reference), not key bytes.
- All key operations (sign, decrypt, unwrap) go through the hardware.
- Attestation may be required before using the key (policy-dependent).
- The hardware backend is responsible for zeroization and destruction.
- Metadata still lives in the vault, and is bound to the handle.

The exact hardware API is defined in Fase 7 (`hardware` module).

---

## 15. Threat-model alignment

This document implements defenses for the following threats from
`THREAT_MODEL.md`:

- **T-02 (key substitution)**: KeyIds are bound into AEAD associated data.
- **T-08 (key misuse)**: purposes are enforced by vault + policy.
- **T-06 (offline vault theft)**: KEKs are derived via Argon2id, DEKs
  are wrapped under KEKs.
- **T-09 (audit log tampering)**: every key op writes to the chained
  audit log.

Threats that affect key management but are out of scope for v1.0:

- **O-01 (compromised OS)**: a rooted OS can capture keys in memory
  during use. Mitigated only by hardware-backed keys.
- **O-03 (cold boot)**: keys in RAM are vulnerable to physical attacks.
  Mitigated by hardware-backed keys or locked memory.

---

## 16. Open questions

- [ ] Concrete format for wrapped key exports (JWE-like? Custom?)
- [ ] Shamir implementation: crate choice, share format
- [ ] Whether to support PKCS#12-style bundles for interop
- [ ] Attestation requirements for hardware-backed keys (which policies?)
- [ ] Key escrow warnings: how to communicate risk to users

Resolved in Fase 3 (Key Management) and Fase 4 (Vault).

---

## 17. References

- `docs/CRYPTOGRAPHY.md` — algorithms used for wrapping, KDF, etc.
- `docs/ARCHITECTURE.md` — vault and policy modules
- `docs/THREAT_MODEL.md` — threats this document defends against
- `docs/SECURITY_MODEL.md` — audit chain and policies
- NIST SP 800-57 — Recommendation for Key Management
- NIST SP 800-133 — Recommendation for Cryptographic Key Generation
- RFC 5869 — HKDF
- RFC 9106 — Argon2

---

*End of document.*

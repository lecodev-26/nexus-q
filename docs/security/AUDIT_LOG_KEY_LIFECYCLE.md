# Audit-log HMAC key lifecycle and rotation design

**Status:** design record for the current F-04 implementation. This document
separates controls that exist today from key-rotation capabilities that are
not implemented. It is not a claim that independent HMAC-key rotation is
available.

## 1. Current key derivation and ownership

The vault audit key is derived while a vault session is unlocked:

```text
audit_key = HKDF-SHA256(
    ikm  = vault_KEK,
    salt = empty,
    info = "nexusq-audit-log-v2",
    L    = 32 bytes
)
```

The implementation is `audit_key()` in `crates/nexusq-core/src/vault/container.rs`.
The input is the already password-derived vault KEK; the audit key is not
independently random and is not a user-managed key. HKDF domain separation
keeps this use distinct from the vault's other key purposes.

The key is held in `Zeroizing<[u8; 32]>` by `AuditLog` and by each active
`AuditSegment`. It is not serialized into segment files, `audit.anchor`, logs,
or event payloads. It exists only in the unlocked process memory and is
zeroized when those owners are dropped. The vault-side `audit_anchor` is an
event hash, not key material, and is stored inside the encrypted vault body.

**Consequences:** anyone who can unlock the vault can derive the current audit
key. Anyone who can read only the audit directory cannot derive it from the
files. Compromise of the vault password/KEK compromises the audit key too.
There is no separate KMS/HSM integration for this key in the core vault path.

## 2. File and process permissions

- Audit segment and anchor temporary files are created exclusively and with
  Unix mode `0600`; writes are synced before atomic replacement.
- The application does not currently enforce permissions on the audit
  directory itself. Operators must place it in a directory owned by the
  service account and restrict directory access (normally `0700`) so an
  untrusted user cannot replace, remove, or enumerate files.
- The vault file and its backups must receive equivalent or stronger
  protection. The encrypted vault-side anchor is part of the rollback
  boundary.
- Do not copy the derived key into environment variables, command-line
  arguments, support bundles, crash reports, or configuration files.

These filesystem controls protect against other local users; they do not
protect against an attacker controlling the service account, process memory,
root, or the host.

## 3. Rotation, revocation, and historical verification

### What exists now

`AuditLog::rotate()` and `max_events` rotate **segments**, not HMAC keys. Every
segment currently uses the same vault-derived audit key. The key derivation
label is fixed at `nexusq-audit-log-v2`.

There is no public API to rotate, revoke, or recover an independent audit HMAC
key, and no password/KEK-change migration that re-authenticates existing audit
segments. Changing the vault KEK or changing the derivation label changes the
audit key; old segments and `audit.anchor` then fail authentication. Do not
change the HKDF label, replace the vault KEK, or manually substitute an audit
key while retaining the existing log directory. Do not describe segment
rotation as key rotation.

### Required design for a future key-rotation implementation

A compatible implementation must be versioned and must not silently
re-authenticate history under a new key. The required properties are:

1. Store a random 256-bit audit-key epoch in the encrypted vault body (or in a
   separately authenticated KMS/HSM keyring). Never store plaintext key bytes
   beside the audit files.
2. Give every epoch a non-secret, monotonically increasing key identifier.
   Bind the identifier and format version into each segment's authenticated
   header and into the tail anchor.
3. Rotate only at a segment boundary. The transition record must bind the
   previous segment hash, old and new key identifiers, and new segment hash;
   authenticate the transition with both the retiring and activating keys.
4. Verify historical segments with their original epoch keys. Retiring a key
   means it can no longer authenticate new writes; it does **not** mean
   deleting it while retained history still depends on it.
5. Permit key destruction only after the corresponding history is expired or
   archived under an independently verifiable checkpoint, according to an
   explicit retention policy. Record the destruction/retirement action in the
   audit chain before it takes effect.
6. Make rotation crash-safe: persist the encrypted keyring update and durable
   transition evidence in a defined order; recovery must either select the
   complete old epoch or the complete new epoch, never guess or silently reset
   to a new genesis.
7. Version the segment and anchor formats, define migration from the current
   single-key format, and reject unknown epochs or missing historical keys
   fail-closed.

Until that design is implemented and tested, the only supported response to
suspected audit-key compromise is to preserve the vault and complete audit
history as evidence, restrict access to the host, and plan a separately
reviewed migration. Starting a fresh audit directory is not a cryptographic
rotation of the old history.

## 4. Recovery and backup

A recoverable backup for audit continuity must contain a mutually consistent
vault snapshot and its complete audit directory, including all numbered
segments and `audit.anchor`. Preserve the credential needed to unlock the
vault separately from the backup. Restore the pair together and verify the
entire chain before resuming writes.

The current F-05 backup bundle deliberately excludes the external audit
folder; import clears `audit_dir` and `audit_anchor` on the restored vault.
Therefore, exporting/importing an F-05 bundle alone restores vault content but
does not restore audit history or resume the previous audit chain. Deployments
that require audit continuity must independently preserve a coordinated copy
of the audit directory and the corresponding vault snapshot. A vault-only
backup cannot reconstruct missing external history; an audit-directory-only
backup has no independent secret with which to verify it.

For incident response, preserve a read-only copy of the original files before
attempting repair. Never regenerate a missing anchor or rewrite old segments
under a new key to make verification pass.

## 5. Rollback, truncation, and reordering model

The implementation uses two local authenticated commitments:

- `audit.anchor` authenticates the current segment number and segment hash
  with the audit HMAC key.
- The encrypted vault body stores the last successfully persisted event hash.

Opening a log checks its complete segment chain and local tail commitment;
unlocking the vault also checks that the vault-side event anchor is still
present in the valid chain. This detects modified events, invalid segment
links, segment reordering/replacement, tail truncation, deletion of the tail,
and rollback of the log while retaining a newer vault snapshot.

**Boundary:** an attacker able to roll back or replace both the vault snapshot
and the entire audit directory to the same older consistent state can defeat
these local checks. To detect that threat, deployments must periodically
publish the current vault identity, segment number, and tail hash to an
independent append-only system or trusted remote checkpoint service. That
external checkpoint is an operational control; the core library does not
currently provide it.

## 6. Verification evidence and regression matrix

The existing implementation includes regression coverage for:

| Scenario | Expected result | Existing coverage |
|---|---|---|
| Valid multi-segment chain | Verify and reopen successfully | `verify_all_accepts_a_fresh_chain`, `rotate_creates_a_second_segment` |
| Event or segment tampering | Reject | `verify_all_detects_a_break`, `tampering_with_the_audit_chain_is_detected` |
| Tail truncation or deletion | Reject | `tail_truncation_is_rejected_by_authenticated_anchor`, `removing_tail_segment_is_rejected_by_authenticated_anchor` |
| Missing tail commitment | Reject | `removing_authenticated_anchor_fails_closed` |
| Stale/replayed valid chain | Reject | `contains_event_hash_rejects_a_replayed_valid_chain` |
| Vault rollback behind persisted audit state | Reject on unlock | `audit_rollback_before_last_persisted_state_is_detected` |
| Wrong HMAC key | Reject | `opening_with_a_different_authentication_key_fails_closed` |

A future key-epoch implementation must add tests for a successful old-to-new
epoch transition, verification of pre-rotation history, rejection of a forged
transition, retirement/revocation behavior, interrupted rotation recovery,
and rejection when a required historical key is unavailable. Passing the
current regression matrix is not evidence that independent key rotation is
implemented.

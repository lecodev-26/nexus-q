# Audit-log HMAC key lifecycle and rotation design

**Status:** implementation record for F-04 segment format v3. Independent
audit-key rotation is implemented through `Session::rotate_audit_key()`;
historical epochs are retained for verification and cannot currently be
retired or destroyed independently.

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

Legacy epoch zero is held as a `Zeroizing<[u8; 32]>` derived from the KEK.
New random 256-bit epoch keys are stored in `VaultBody::audit_key_epochs`,
which is serialized only inside the vault AEAD envelope. `AuditLog` and active
segments keep zeroizing key copies in process memory. The epoch identifier is
non-secret and appears in v3 segment headers and NQA4 anchors; key bytes never
appear in the audit directory, logs, or event payloads. The vault-side
`audit_anchor` remains an event hash, not key material.

Anyone able to unlock the vault can access retained epoch keys. Anyone able
to read only the audit directory cannot derive them. Compromise of the vault
password/KEK therefore compromises the encrypted keyring too. There is no
separate KMS/HSM integration.

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

### Implemented rotation

`Session::rotate_audit_key()` creates a fresh random 256-bit key and 128-bit
epoch identifier using the OS CSPRNG. It retains all previous epochs in the
encrypted vault body, marks the new epoch current, and persists that body
before changing the audit log. The log then closes the previous segment and
creates a new v3 segment linked to the old segment hash. A `key_rotated` event
is appended under the new epoch.

F-04 v3 stores the epoch identifier in the segment header and includes it in
the HMAC segment commitment. This prevents changing the epoch identifier
without invalidating the segment. Legacy v2 segments are interpreted as epoch
zero and retain their original hash formula and wire version when read or
saved. NQA4 anchors authenticate the segment number, epoch identifier, and
segment hash; NQA3 anchors remain supported for legacy logs.

Rotation ordering is recoverable: the encrypted keyring/current-epoch marker
is durable before the new segment is created. If interrupted before segment
creation, unlock completes the switch. If the new segment is durable but
its anchor replacement is not, unlock accepts only the one-segment predecessor
anchor whose epoch and hash match the authenticated preceding segment and the
new segment's `prev_segment`, then repairs the anchor. Unknown epoch IDs, missing keys, malformed key lengths, duplicate
epoch IDs, and unrelated/stale anchors fail closed.

Historical keys are retained so every old segment remains verifiable. The
current API does not delete or cryptographically revoke historical keys, does
not support KMS/HSM custody, and does not publish external checkpoints. The
new segment is linked to the prior segment hash; the transition is not a
separate dual-signature certificate. Deployments needing stronger transition
attestation or independent rollback resistance should add an external
append-only checkpoint before relying on those properties.

`AuditLog::rotate()` and `max_events` continue to rotate segments only; they
do not create new key epochs. Use `Session::rotate_audit_key()` for key
rotation. Changing the vault KEK still requires a separate migration that
preserves the encrypted audit keyring and audit history.

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

- `audit.anchor` authenticates the current segment number, key epoch ID, and
  segment hash with the corresponding audit HMAC key (NQA4; NQA3 is legacy).
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

The key-epoch regression coverage includes a successful old-to-new transition,
verification of pre-rotation history after reopen, legacy v2 segment parsing,
and fail-closed behavior when a required epoch is unavailable. Retirement and
cryptographic revocation remain unsupported and must not be claimed.

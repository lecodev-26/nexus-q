# HSM CA recovery and M-of-N procedure

This document describes an operational control flow, not a way to export CA private keys.

## Initial provisioning

1. Select a supported PKCS#11 token and record the module path, token serial, firmware/version and supported ML-DSA-65 mechanisms. Verify `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false` on the private object.
2. Create the production token and assign a unique, non-reused object label. Retrieve the token PIN from a secret manager; do not put it in shell history, source control, logs or CI output.
3. Register the M-of-N custodian public keys through an out-of-band identity-verification procedure. Keep each custodian's Ed25519 approval private key under that custodian's control.
4. Start a ceremony request and distribute the exact transcript. Each custodian verifies the operation, label, expiry and nonce independently, then signs `CeremonyRequest::approval_payload()`.
5. Finalize only after the configured quorum is met. Record the returned key reference and public key; verify that the CA certificate's public key matches the HSM signer before activating the CA.
6. Forward ceremony events and enrollment audit events to durable append-only storage. The in-memory snapshots are not a recovery source.

## Backup and restore

- Use only the HSM vendor's supported encrypted backup/replication mechanism and its own M-of-N or split-knowledge controls. Do not extract or serialize the private key to a file.
- Store backup media and recovery credentials in separate physical/security domains. Require independent custodians for backup creation and restore authorization.
- Perform a scheduled restore drill to a clean, isolated token of the same supported model/firmware. Rebind the restored token by its new serial number, verify the public key fingerprint, sign a test message, and validate the signature before making it active.
- Restore the durable key-reference registry, certificate chain, serial allocator, policy and audit sink from authenticated backups. Do not restore an old serial counter without checking that it cannot collide with already issued certificates.
- If the HSM or its administrative secret is lost or compromised, suspend issuance, preserve audit evidence, revoke/replace the CA according to the PKI policy, and conduct a new M-of-N ceremony. Do not attempt an undocumented private-key export.

## Ceremony controls

- Threshold `M` must be non-zero and no greater than `N`; use a threshold approved by the organization's security policy.
- Approvals are bound to a random nonce, action, label, creation time and expiry. A changed request must be rejected and restarted as a new ceremony.
- Duplicate approvals do not count twice. Finalization is one-shot; the same ceremony cannot generate a second key.
- The current coordinator keeps its state and event snapshot in memory only. Do not rely on it for restart-safe governance until a durable transactional store and audit sink are integrated.

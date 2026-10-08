# V2 Security Follow-ups — Issue #20

This document records the disposition of the non-red/non-orange items from the
security review tracked by GitHub Issue #20. These items are deliberately kept
separate from vulnerability remediation.

## Hardware backends

The software backend returns `NotSupported` for hardware key-provider and
attestation operations. This is intentional: NEXUS-Q does not claim TPM, HSM,
or Secure Element protection on a platform where no such provider exists.
Hardware integration remains a future backend task. Documentation may describe
supported interfaces and future integration points, but must not imply that the
software backend provides hardware isolation.

## C/Python SDKs

The C and Python bindings are thin API layers over the Rust core. Their current
scope is documented as such. API expansion is product/ergonomics work, not a
security remediation, and must preserve the core security semantics rather than
reimplement cryptography in the bindings.

## Hybrid KEM naming

NEXUS-Q currently implements the documented ML-KEM-768 + X25519 combiner based
on the active X-Wing Internet-Draft, including the transcript-bound SHA3-256
input and domain-separation label. The ML-KEM-1024 + X25519 variant is a
separate NEXUS-Q-specific construction.

NEXUS-Q **does not claim conformance to a finalized X-Wing standard**. Public
claims must use the exact construction/documentation supported by the code and
its pinned evidence. This distinction also applies to the threat model and
customer-facing cryptography documentation.

## Audit-event completeness

The audit enum contains lifecycle/event identifiers beyond those currently
emitted by every high-level operation. Existing security-critical transitions
are emitted, including key creation/activation/use/rotation/revocation/
destruction, identity and credential lifecycle, envelope seal/open, policy
changes, audit configuration, and denied access.

The following event identifiers are currently reserved/defined but do not have
an independent high-level emission path in `nexusq-core`:

| Event | Current disposition |
|---|---|
| `KeyExported` | Reserved for a future explicit key-export operation |
| `BackupExported` | Backup module operation is not coupled to a Vault audit context |
| `BackupImported` | Backup module operation is not coupled to a Vault audit context |
| `VaultLocked` | Session lock path has no independent event emission |
| `VaultSealed` | Vault seal operation has no independent event emission |
| `SessionEnded` | Session lifecycle is currently represented by lock/ownership semantics |
| `MigrationPerformed` | No migration transition is currently performed by the active format path |

This is an **audit-completeness limitation, not a cryptographic bypass**. New
high-level operations must add an event emission where the operation has a
security-relevant transition. Adding an event must not record plaintext,
passwords, private keys, KEKs, signatures, or other secret material.

## Hardware and audit evidence

The existing software-backend tests verify `NotSupported` behavior for
hardware-only operations. The audit event enum has stable canonical string
identifiers and hash-chain coverage. Future audit expansion should add
operation-level tests rather than merely adding enum variants.

## Acceptance

Issue #20 is considered addressed when:

- hardware limitations remain explicit and honest;
- C/Python scope is documented as API/ergonomics work;
- hybrid-KEM claims distinguish the active X-Wing draft construction from a
  finalized standard;
- audit-event gaps are explicitly documented and cannot be mistaken for
  security coverage that does not exist;
- no unsupported security, standards-conformance, or hardware-isolation claim
  is introduced.

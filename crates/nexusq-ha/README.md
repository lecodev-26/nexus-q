# NexusQ HA and tenant isolation primitives

`nexusq-ha` provides the durable building blocks for the multi-tenant CA/OCSP cluster in issue #69:

- Validated tenant IDs, a durable tenant catalog, per-tenant issuance switches and isolated request quotas.
- Per-tenant append-only journals with owner-only file permissions, fsynced prepare/commit/abort frames, SHA-256 hash chains and startup integrity validation.
- A replication coordinator that fences writes using a consensus-issued leader lease, requires a majority of durable prepare acknowledgements, and only reports a commit after a majority confirms it. Ambiguous commits return an explicit reconciliation error; callers must inspect journal state before retrying.
- Integrity-checked atomic snapshots and restore into a new empty journal. Snapshots preserve sequence gaps and reject cross-tenant or tampered state.
- Recovery objective validation for RPO <= 1 hour and RTO <= 4 hours, plus per-tenant rate limits.

## Cluster integration contract

This crate deliberately does **not** implement its own consensus algorithm or network transport. The deployment must supply authenticated `ReplicaPeer` implementations and a lease/fencing provider backed by a consensus system. Each peer must call `accept_replica_prepare`, `accept_replica_commit`, and `accept_replica_abort` only after authenticating the sender and persisting the requested frame. Never expose these operations on a public network or trust a tenant-provided node identity. The current coordinator is a replication/fencing core, not a turnkey multi-node server by itself.

Before connecting the CA and OCSP runtime to this layer, persist certificate serial allocation, CA policy changes, revocation mutations, CRL numbers and tenant catalog changes in the same transactional workflow. Private keys must remain in the configured HSM/key provider; do not place key material, passwords or bearer tokens in journal payloads. Snapshots are integrity-protected but not encrypted in this issue; use the encrypted backup controls from issue #70 for backup media.

## Recovery runbook

1. Fence the failed leader through the consensus-backed lease provider and increment the fencing epoch.
2. Confirm a quorum is reachable. Reconcile every pending prepare against the quorum before accepting new writes; never discard an unresolved transaction solely because the old leader disappeared.
3. Restore a verified snapshot into a clean journal, replay committed replicated records, verify the hash chain and tenant catalog, then rebind the node to the correct CA certificate fingerprints.
4. Validate serial allocation and CRL numbers cannot collide with issued certificates, test OCSP `good`/`revoked`/`unknown`, and only then enable issuance.
5. Measure RPO from the last quorum-confirmed replicated commit and RTO from the incident start. Alert when the one-hour/four-hour objectives cannot be met.

`cargo test -p nexusq-ha` covers tenant isolation, durable catalog restart, journal persistence, quorum/fencing, snapshot restore with sequence gaps, snapshot tampering, recovery-objective bounds and independent tenant rate limits.

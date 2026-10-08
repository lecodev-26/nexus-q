# NEXUS-Q v2 Security Hardening — Issue #22

## Audit integrity

The audit chain now has two authenticated commitments:

1. the encrypted vault-side event anchor, and
2. `audit.anchor`, an HMAC-authenticated commitment to the current segment number and segment hash.

The tail commitment is refreshed only after the segment write is durable and is itself published with exclusive temporary-file creation followed by atomic rename. Opening an audit log requires the commitment to exist and match the complete on-disk tail. Consequently, deletion, truncation, reordering/replacement, or removal of the tail commitment fails closed.

`remove_audit_dir()` records `AuditRemoved` before disabling the sink.

## Policy boundary

A decrypted `Session` is the authenticated administrative boundary. Policy administration remains available to that session, while the generic `body_mut()` escape hatch is crate-internal and cannot be used by downstream callers to bypass policy checks. Once a policy set is attached, missing rules are denied; with no policy set attached, the documented behavior is permissive.

## Fuzzing

The existing parser targets remain. Coverage was deepened so envelope fuzzing can reach the hybrid KEM opening path, credential fuzzing reaches signature verification dispatch, vault parsing uses collision-safe temporary files, and backup-import fuzzing exercises authenticated backup handling. Extended V2 fuzzing remains five minutes per target; the main/release security workflow remains the separate 45-minute gate.

## Hybrid benchmark

A dedicated CI benchmark runs the production ML-KEM-768 + X25519 encapsulation/decapsulation path with 1,000 measured samples and 100 warmups. It records CPU model/features, compiler/toolchain, release profile, implementation identity, and mean/p50/p95/p99 latency. This is an evidence gate, not a claim of cross-machine superiority.

## Secure memory and RNG

The portable software backend does not claim `mlock`: its current Unix implementation returns `NotSupported`, while secret buffers remain zeroized. `MixedRandomSource` is available through the hardware backend's `RandomSource` interface, but the core cryptographic key-generation paths continue to instantiate the OS CSPRNG directly; documentation does not claim TRNG mixing is the default core key-generation path.

## Temporary files

Vault, backup, audit-segment, and audit-anchor temporary files use exclusive `create_new()` creation. Random names are only a collision-reduction mechanism; exclusivity is the security invariant.

## Deliberate release gates

The broader statistical Arena methodology and final PQC performance acceptance remain V2-10 release-gate work. The hardening issue adds the production hybrid benchmark evidence without inventing an arbitrary hardware-independent performance threshold.

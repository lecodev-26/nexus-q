# NEXUS-Q v1.0 — Frozen engineering baseline

NEXUS-Q v1.0 is the project's completed engineering baseline as of 2026-10-05. It is preserved as the reference point for v2.

## What is complete

- Core cryptography, vault, envelope, identity, policy, storage and CLI implementation.
- Observability and deployment documentation.
- User documentation and troubleshooting guides.
- SDK/binding baseline and CI validation.
- Security CI including secret scanning, dependency/security gates, fuzz harness builds and extended parser fuzzing.
- PQC Benchmark Arena with pinned external implementations and normalized JSONL results.
- Deterministic release packaging and metadata.

## What v1 does not claim

- No independent external cryptographic/security audit has been performed.
- No public registry/package release is being made at this checkpoint.
- v1 is not a performance leader. Arena measurements show material latency gaps versus the fastest comparators on ML-KEM and ML-DSA.
- Hardware-specific capabilities remain bounded by the documented backend/runner availability.

## Performance baseline

The exact Arena measurements are recorded in [`BENCHMARKS.md`](../BENCHMARKS.md). These measurements are the starting point for v2 optimization and must not be replaced by selective or synthetic numbers.

## v2 hand-off

The `nexusqv2` branch became the completed V2 continuation line. V1 remains the frozen compatibility and benchmark reference. PR #37 integrated the frozen V2 line into `main` after the required compatibility CI passed; the post-merge `main` CI is now the final validation checkpoint before public V2 release.

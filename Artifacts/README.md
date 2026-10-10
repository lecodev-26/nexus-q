# CI Artifacts Archive

This directory preserves generated NEXUS-Q V4 CI outputs in Git, independently of GitHub Actions artifact retention.

- `v4-issue23-measurement/<run-id>-<attempt>/`: matched-host Rust/AWS-LC benchmark outputs, raw JSONL, host/toolchain metadata, and runner binaries produced by the measurement workflow.
- `v4-issue23-phase0/<run-id>-<attempt>/`: dependency provenance, Cargo metadata, toolchain identity, and Phase 0 evidence.

Each run directory includes a `README.txt` with its workflow run ID, source commit, ref, and Actions URL. These files are archival evidence, not a claim that Phase 0 is complete or that either implementation is faster. The workflows also upload their outputs as normal Actions artifacts for convenient download. Archive-only commits are excluded from triggering new Phase 0/measurement runs.

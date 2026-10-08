# NEXUS-Q v2 — Security Regression and Fuzzing

## Scope

V2-09 adds a dedicated security gate for nexusqv2. The gate combines:

- Rust formatting and strict Clippy validation.
- Full workspace tests.
- cargo audit dependency advisory checks.
- cargo deny check supply-chain/license/source policy checks.
- Locked dependency metadata retained as a CI artifact.
- Build coverage for all existing and added libFuzzer targets.
- Extended fuzzing for vault/envelope boundaries plus credential verification and backup import, including collision-safe temporary-file handling.
- Repository secret scanning.

The V2 workflow checks out Git submodules recursively so the correctness/interoperability vector suite remains reproducible.

## Fuzz duration

The retained fuzz policy is **5 minutes per extended target**:

- vault_parse: -max_total_time=300, CI timeout 5 minutes.
- envelope_parse: -max_total_time=300, CI timeout 5 minutes.
- backup_import: -max_total_time=300, CI timeout 5 minutes.

This is intentional. Longer multi-hour soaking is not part of the V2 PR gate.

The existing main-branch security workflow uses the same 5-minute limits so the release/security policy is consistent across V2 and main.

## Security invariants

V2-09 does not change cryptographic parameters, algorithms, wire formats, zeroization semantics, or public security policy.

The purpose of this phase is regression detection and adversarial-input coverage, not performance optimization.

A fuzz finding is a release blocker until it is triaged, reproduced, fixed, and covered by a regression test where appropriate.

## Evidence retained

The PR/CI run is the authoritative evidence for:

1. security regression checks,
2. fuzz-target build coverage,
3. 5-minute parser fuzz runs,
4. dependency audit/deny results,
5. secret scanning.

This phase is an internal engineering security gate, not an independent external security audit.

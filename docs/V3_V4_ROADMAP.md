# NEXUS-Q version history and current V4 status

Updated: 2026-10-19

This document describes the repository as it exists on `main`. It is a status record, not a declaration that NEXUS-Q is production-ready or that all planned integration work is complete. The workspace is versioned 4.1.0 (stable line release); the `v4.1.0` tag and GitHub release are cut after PR #55 merges and its four-hour fuzz soaks are green, via the tag-gated `v4-release.yml` gate and `docs/V4_RELEASE.md`.

## Version lines

| Line | Reference | Role | Current status |
|---|---|---|---|
| V1 | tag [`v1.0.0`](https://github.com/lecodev-26/nexus-q/releases/tag/v1.0.0) | Original baseline | Frozen engineering baseline |
| V2 | branch `nexusqv2`, tag [`v2.0.0`](https://github.com/lecodev-26/nexus-q/releases/tag/v2.0.0) | Security, correctness/interoperability and release-gate work | Frozen engineering line |
| V3 | branch `nexusqv3`, tag [`v3-engineering-2026-10-09`](https://github.com/lecodev-26/nexus-q/releases/tag/v3-engineering-2026-10-09) | Hardened implementation, reproducible Arena and retained evidence | Engineering release |
| V4 | branch `nexusqv4`, tag [`v4-engineering-2026-10-16`](https://github.com/lecodev-26/nexus-q/tree/v4-engineering-2026-10-16) | Experimental native backend and performance work | Integrated into `main`; production-path wiring completed by PR #55 |
| V4.1 | workspace version `4.1.0`, tag `v4.1.0` (cut after the PR #55 merge and green soaks) | Stable line release of the V4 work | Current stable line, ready for the final independent audit (Phase 21) |

## Current `main` snapshot

- Merge PR: [#54](https://github.com/lecodev-26/nexus-q/pull/54).
- Merge commit: [`1c03968e9b8d5578020e571e2f25edc5a7165607`](https://github.com/lecodev-26/nexus-q/commit/1c03968e9b8d5578020e571e2f25edc5a7165607).
- Engineering tag: [`v4-engineering-2026-10-16`](https://github.com/lecodev-26/nexus-q/tree/v4-engineering-2026-10-16).
- The native backend is present as an experimental, separately buildable implementation.
- The official benchmark gate passed with the unchanged limit of 1.5× for median and p95 in the reviewed CI run. That result applies to the measured backend operations; it is not an end-to-end application benchmark.
- **The backend is not yet connected to `nexusq-core`, CLI, or SDK production cryptographic paths.** The current production-facing code must not be described as using this backend until that wiring is implemented and verified.
- A GitHub engineering tag or draft release does not mean the project has completed its remaining engineering work, received an independent audit, obtained FIPS 140-3 validation, or published packages to external registries.

## Branches

The intended retained branches are `main`, `nexusqv2`, `nexusqv3`, and `nexusqv4`. Temporary diagnostic/integration branches were removed after the V4 snapshot was integrated. Historical commits and evidence should be followed through their commit links, tags and archived artifacts rather than assuming old branch names still exist.

## Evidence and historical records

- [`../artifact-archive/README.md`](../artifact-archive/README.md) indexes retained artifacts, provenance, checksums and limitations.
- [`../artifact-archive/research-results/issue-41-v1-v3-latency-root-cause.md`](../artifact-archive/research-results/issue-41-v1-v3-latency-root-cause.md) documents V1/V3 paired observations and separates evidence from unproven causal explanations.
- [`performance/NATIVE_BACKEND.md`](performance/NATIVE_BACKEND.md) documents native-backend architecture and detailed benchmark evidence.
- [`performance/history/`](performance/history/) preserves dated audits and historical execution records. Those records describe the code and CI state at the time and should not be treated as current status when later evidence supersedes them.

## Engineering boundary

The next production-integration work is deliberately separate from the completed V4 snapshot. It must connect the native backend to the real `nexusq-core` ML-KEM/ML-DSA call paths before claiming production use, then verify differential correctness, standardized test vectors, fallback/dispatch behavior, security properties, CLI/SDK behavior and end-to-end performance. The 1.5× gate must not be weakened, and isolated kernel/backend measurements must not be represented as full application-path measurements.

The former Issue #48 tracking issue is closed by project decision. Its checklist and supporting migration notes are retained as historical records, not as an active tracker or a claim that every original checklist item is complete.

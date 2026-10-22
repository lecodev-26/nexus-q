# NEXUS-Q version history and current V4 status

Updated: 2026-10-19

This document describes the repository as it exists on `main`. It is a status record, not a declaration that NEXUS-Q is production-ready or that all planned integration work is complete. The current local development branch is preparing the 4.1.1 release candidate. The published 4.1.0 line and its historical tag remain immutable. The 4.1.1 release must wait for branch CI, the required fuzz soaks, post-merge validation, resolution of the existing remote `4.1.1` SwiftPM tag collision, and explicit publication authorization; see `docs/V4_RELEASE.md`.

## Version lines

| Line | Reference | Role | Current status |
|---|---|---|---|
| V1 | tag [`v1.0.0`](https://github.com/lecodev-26/nexus-q/releases/tag/v1.0.0) | Original baseline | Frozen engineering baseline |
| V2 | branch `nexusqv2`, tag [`v2.0.0`](https://github.com/lecodev-26/nexus-q/releases/tag/v2.0.0) | Security, correctness/interoperability and release-gate work | Frozen engineering line |
| V3 | branch `nexusqv3`, tag [`v3-engineering-2026-10-09`](https://github.com/lecodev-26/nexus-q/releases/tag/v3-engineering-2026-10-09) | Hardened implementation, reproducible Arena and retained evidence | Engineering release |
| V4 | branch `nexusqv4`, tag [`v4-engineering-2026-10-16`](https://github.com/lecodev-26/nexus-q/tree/v4-engineering-2026-10-16) | Experimental native backend and performance work | Integrated into `main`; production-path wiring completed by PR #55 |
| V4.1.1 | workspace/package candidate `4.1.1`; branch `work/4.1.1-development` | Release candidate with issues #64–#71 integrated locally | Awaiting hosted branch CI, required fuzz soaks, post-merge CI, and explicit publication approval; independent external audit remains open |
| V4.1 | workspace version `4.1.0`, tag `v4.1.0` | Previous stable line release of the V4 work | Historical release record; not overwritten by the 4.1.1 candidate |

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

The native backend is now connected to the real `nexusq-core` ML-KEM/ML-DSA call paths behind the explicit `native-backend` Cargo feature; RustCrypto remains the default and the native feature remains experimental and off by default. See [`performance/NATIVE_BACKEND_PRODUCTION_WIRING.md`](performance/NATIVE_BACKEND_PRODUCTION_WIRING.md) for integration scope and historical benchmark evidence, and [`security/issue-71-kernel-integration.md`](security/issue-71-kernel-integration.md) for the local validation record. Remaining release gates include the required long fuzz soaks on the exact candidate SHA and review of all current CI evidence. The Valgrind constant-time harness is one assurance signal, not a proof of constant-time behavior. Do not promote the native backend to the default or claim production readiness while those gates and the independent external audit remain open. The 1.5× median-and-p95 performance gate must not be weakened, and isolated kernel/backend measurements must not be represented as full application-path measurements.

The former Issue #48 tracking issue is closed by project decision. Its checklist and supporting migration notes are retained as historical records, not as an active tracker or a claim that every original checklist item is complete.

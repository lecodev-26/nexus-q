# NEXUS-Q V1–V4 version history and transition plan

Updated: 2026-10-15

## Version lines

| Version | Branch / reference | Role | Status |
|---|---|---|---|
| V1 | tag `v1.0.0` | Frozen original baseline for compatibility and performance comparisons | Historical baseline |
| V2 | `nexusqv2`, tag `v2.0.0` | Security hardening, correctness/interoperability and fuzz/release-gate work | Frozen engineering line; retained for reproducibility |
| V3 | engineering snapshot tag `v3-engineering-2026-10-09`, branch `nexusqv3`, PR [#45](https://github.com/lecodev-26/nexus-q/pull/45) | Hardened PQC implementation, reproducible benchmark tooling, security hardening, documentation and evidence archive | Integrated into `main`; post-merge Security/Release Gates, Security Regression/Fuzzing, and SDK CI all green on `fbd3fbe1d4fe38d52f58a47e11096fb4ab5bee45`; all three 4-hour fuzz soaks completed successfully |
| V4 | branch `nexusqv4` | Native-backend and architecture-specific performance-kernel experiments | Experimental backend merged by PRs [#51](https://github.com/lecodev-26/nexus-q/pull/51) and [#50](https://github.com/lecodev-26/nexus-q/pull/50); 1.5× gate passed on the tested pre-integration head; integrated CI, docs, four-hour fuzzing, audit and release decision remain pending |

## Evidence and artifacts

- [`../artifact-archive/README.md`](../artifact-archive/README.md) indexes the archived artifacts, their provenance, checksums and limitations.
- [`../artifact-archive/research-results/issue-41-v1-v3-latency-root-cause.md`](../artifact-archive/research-results/issue-41-v1-v3-latency-root-cause.md) documents the V1/V3 paired benchmark observations and separates supported findings from unproven causal explanations.
- The archive includes raw JSONL and environment metadata from Arena run [37918298351](https://github.com/lecodev-26/nexus-q/actions/runs/37918298351) and security-gate artifacts from run [37918321901](https://github.com/lecodev-26/nexus-q/actions/runs/37918321901), plus earlier recovered ZIP snapshots. It is not a claim that every historical Actions artifact has been recovered.

## V3 closure record

1. Issue #41 is closed by an explicit project decision: V1 prioritizes speed; V3 retains the security hardening and accepts its observed performance cost. Archived measurements are evidence, not proof that every individual delta is caused by zeroization.
2. PR #42, #44 and #45 are merged. V3 Incremental CI and PQC Benchmark Arena passed. Post-merge CI on `main` at commit `fbd3fbe1d4fe38d52f58a47e11096fb4ab5bee45` passed: [Security and Release Gates](https://github.com/lecodev-26/nexus-q/actions/runs/37924236952), [Security Regression and Fuzzing](https://github.com/lecodev-26/nexus-q/actions/runs/37924236978), and [SDK CI](https://github.com/lecodev-26/nexus-q/actions/runs/37924237015). The vault, envelope, and backup-import four-hour fuzz jobs all completed successfully.
3. Local format/diff checks passed and every entry in `artifact-archive/SHA256SUMS-2026-10-09.txt` verified.
4. V3 is closed as an engineering milestone, not as an independent security certification or registry release. Preserve zeroization and security controls; V4 optimizations must retain the hardened behavior. No crates.io, PyPI, or other SDK registry packages are published as part of this closure.

## V4 performance-kernel entry criteria

1. Start from the reviewed V3 snapshot and retain the portable implementation as a reference/fallback.
2. Work under Issue #23. Prototype AVX2 for supported x86_64 and NEON for supported AArch64 behind explicit target-feature dispatch.
3. Require differential tests against the reference path, KATs and applicable Wycheproof tests, fuzzing, constant-time/security review, and benchmarks on matched hardware.
4. Compare operation-level median, p95 and dispersion over at least three independent runs; keep cached verification distinct from conventional verification.
5. Do not call V4 released, merge experimental kernels by default, or publish performance claims until evidence and release gates support them.

## Branch hygiene

The intended long-lived branches are `main`, `nexusqv2`, `nexusqv3`, and `nexusqv4`. Delete diagnostic or temporary branches only after verifying their unique commits and artifacts are merged or preserved in the archive. Do not delete `nexusqv2` or `nexusqv3`. Issue #41 is closed under the documented speed-versus-security decision. Issue #23 was closed as a historical/superseded tracker on 2026-10-15; that administrative closure does not assert that every original acceptance criterion is complete. Remaining V4 validation is tracked by the active integration and release-readiness work. PR #46 was also closed as historical, not as evidence that its original checklist completed.

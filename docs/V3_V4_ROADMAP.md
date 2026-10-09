# NEXUS-Q V1–V4 version history and transition plan

Updated: 2026-10-09

## Version lines

| Version | Branch / reference | Role | Status |
|---|---|---|---|
| V1 | tag `v1.0.0` | Frozen original baseline for compatibility and performance comparisons | Historical baseline |
| V2 | `nexusqv2`, tag `v2.0.0` | Security hardening, correctness/interoperability and fuzz/release-gate work | Frozen engineering line; retained for reproducibility |
| V3 | `nexusqv3`, PR [#44](https://github.com/lecodev-26/nexus-q/pull/44) | Hardened PQC implementation, reproducible benchmark tooling, security hardening, documentation and evidence archive | Integrated into `main` by PR #44; post-merge CI is the final integration gate |
| V4 | planned branch `nexusqv4` | Assembly/architecture-specific performance-kernel experiments | Planned; issue [#23](https://github.com/lecodev-26/nexus-q/issues/23) remains the source of work |

## Evidence and artifacts

- [`../artifact-archive/README.md`](../artifact-archive/README.md) indexes the archived artifacts, their provenance, checksums and limitations.
- [`../artifact-archive/research-results/issue-41-v1-v3-latency-root-cause.md`](../artifact-archive/research-results/issue-41-v1-v3-latency-root-cause.md) documents the V1/V3 paired benchmark observations and separates supported findings from unproven causal explanations.
- The archive includes raw JSONL and environment metadata from Arena run [37918298351](https://github.com/lecodev-26/nexus-q/actions/runs/37918298351) and security-gate artifacts from run [37918321901](https://github.com/lecodev-26/nexus-q/actions/runs/37918321901), plus earlier recovered ZIP snapshots. It is not a claim that every historical Actions artifact has been recovered.

## Open work before declaring V3 complete

1. Issue #41 is closed by an explicit project decision: V1 prioritizes speed; V3 retains the security hardening and accepts its observed performance cost. Archived measurements are evidence, not proof that every individual delta is caused by zeroization.
2. PR #42 and PR #44 are merged. The post-merge CI on `main` must finish and its actual conclusions must be reviewed before any further promotion/cleanup. Jobs marked skipped are not evidence that their underlying soak/test completed.
3. Preserve security properties. Do not disable zeroization or weaken controls to chase latency. V4 optimizations must preserve the hardened behavior.

## V4 performance-kernel entry criteria

1. Start from the reviewed V3 snapshot and retain the portable implementation as a reference/fallback.
2. Work under Issue #23. Prototype AVX2 for supported x86_64 and NEON for supported AArch64 behind explicit target-feature dispatch.
3. Require differential tests against the reference path, KATs and applicable Wycheproof tests, fuzzing, constant-time/security review, and benchmarks on matched hardware.
4. Compare operation-level median, p95 and dispersion over at least three independent runs; keep cached verification distinct from conventional verification.
5. Do not call V4 released, merge experimental kernels by default, or publish performance claims until evidence and release gates support them.

## Branch hygiene

The intended long-lived branches are `main`, `nexusqv2`, `nexusqv3`, and `nexusqv4`. Delete diagnostic or temporary branches only after verifying their unique commits and artifacts are merged or preserved in the archive. Do not delete `nexusqv2` or `nexusqv3`. Do not close Issue #23. Issue #41 is closed under the documented speed-versus-security decision. Do not close Issue #23 until its own implementation and validation criteria are met.

# NEXUS-Q V1–V4 version history and transition plan

Updated: 2026-10-09

## Version lines

| Version | Branch / reference | Role | Status |
|---|---|---|---|
| V1 | tag `v1.0.0` | Frozen original baseline for compatibility and performance comparisons | Historical baseline |
| V2 | `nexusqv2`, tag `v2.0.0` | Security hardening, correctness/interoperability and fuzz/release-gate work | Frozen engineering line; retained for reproducibility |
| V3 | `nexusqv3`, PR [#44](https://github.com/lecodev-26/nexus-q/pull/44) | Hardened PQC implementation, benchmark reproducibility, dependency/profile diagnostics, documentation and evidence archive | Integration review; do not claim promoted to `main` until required checks and review complete |
| V4 | planned branch `nexusqv4` | Assembly/architecture-specific performance-kernel experiments | Planned; issue [#23](https://github.com/lecodev-26/nexus-q/issues/23) remains the source of work |

## Evidence and artifacts

- [`../artifact-archive/README.md`](../artifact-archive/README.md) indexes the archived artifacts, their provenance, checksums and limitations.
- [`../artifact-archive/research-results/issue-41-v1-v3-latency-root-cause.md`](../artifact-archive/research-results/issue-41-v1-v3-latency-root-cause.md) documents the V1/V3 paired benchmark observations and separates supported findings from unproven causal explanations.
- The archive includes raw JSONL and environment metadata from Arena run [37918298351](https://github.com/lecodev-26/nexus-q/actions/runs/37918298351) and security-gate artifacts from run [37918321901](https://github.com/lecodev-26/nexus-q/actions/runs/37918321901), plus earlier recovered ZIP snapshots. It is not a claim that every historical Actions artifact has been recovered.

## Open work before declaring V3 complete

1. Finish the forensic acceptance criteria for [Issue #41](https://github.com/lecodev-26/nexus-q/issues/41): isolate dependency source, feature/zeroize, and profile effects; run at least three comparable Arena jobs; report robust statistics; and document the ML-KEM cause only when demonstrated.
2. Finish review and required CI on PR #42 before merging the benchmark work into `nexusqv3`.
3. Finish PR #44 review and required checks before promoting V3 to `main`. Jobs marked skipped are not evidence that their underlying soak/test completed.
4. Preserve security properties. Do not disable zeroization or weaken controls to chase latency.

## V4 performance-kernel entry criteria

1. Start from the reviewed V3 snapshot and retain the portable implementation as a reference/fallback.
2. Work under Issue #23. Prototype AVX2 for supported x86_64 and NEON for supported AArch64 behind explicit target-feature dispatch.
3. Require differential tests against the reference path, KATs and applicable Wycheproof tests, fuzzing, constant-time/security review, and benchmarks on matched hardware.
4. Compare operation-level median, p95 and dispersion over at least three independent runs; keep cached verification distinct from conventional verification.
5. Do not call V4 released, merge experimental kernels by default, or publish performance claims until evidence and release gates support them.

## Branch hygiene

The intended long-lived branches are `main`, `nexusqv2`, `nexusqv3`, and `nexusqv4`. Delete diagnostic or temporary branches only after verifying their unique commits and artifacts are merged or preserved in the archive. Do not delete `nexusqv2` or `nexusqv3`. Do not close Issue #23. Close Issue #41 only after its explicit acceptance criteria are met—not merely because a related PR or one CI run is green.

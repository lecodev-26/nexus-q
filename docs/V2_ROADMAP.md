# NEXUS-Q v2 — Roadmap

Status: **design complete; implementation proceeds issue-by-issue on `nexusqv2`.**

## Execution contract

Each phase is implemented on a working issue branch, validated with tests/benchmarks/security gates, reviewed in a PR, and merged into `nexusqv2`. A roadmap phase is marked complete **only after its issue acceptance criteria are satisfied and the PR is merged**. Evidence is retained in the issue/PR and CI artifacts.

Public package publication is intentionally deferred until V2-12 and the individual registry/package gates pass.

## Objective

NEXUS-Q v1 is the frozen engineering baseline. The v1 PQC Benchmark Arena established the optimization target: NEXUS-Q is functional and validated, but mature comparators are faster, with the largest gap in ML-DSA.

v2 objective: materially improve ML-KEM-768/1024 and ML-DSA-65 performance through benchmark-first, profile-driven optimization while preserving correctness, interoperability, security semantics and portable fallbacks.

## Non-negotiable rules

- Do not optimize before the relevant benchmark/profile evidence exists.
- Every retained performance change must show reproducible benefit.
- Correctness, security and interoperability outrank speed.
- Do not change cryptographic parameters or security semantics for performance.
- Keep portable scalar fallbacks for optimized CPU paths.
- Do not claim performance leadership without Arena evidence.
- If V2-10 fails its target, return to profiling/optimization rather than weakening the gate.
- Public registry/package publication happens only after V2-12 and each package's own release gate.

## V2 phases

- [x] **V2-01 — Lock reproducible benchmark baseline** — reproduce and lock v1 ML-KEM/ML-DSA measurements and conditions. Issue #1.
- [x] **V2-02 — Profile ML-KEM and ML-DSA hotspots** — produce quantitative hotspot and optimization map. Issue #2.
- [x] **V2-03 — Optimize ML-KEM** — improve ML-KEM-768/1024 from measured hotspots. Issue #3.
- [x] **V2-04 — Optimize ML-DSA** — improve ML-DSA-65 from measured hotspots. Issue #4.
- [x] **V2-05 — Optimize memory and allocations** — remove measurable avoidable memory/copy/allocation costs without weakening zeroization. Issue #5.
- [x] **V2-06 — Evaluate SIMD and CPU backends** — add only measured, safely dispatched acceleration with scalar fallback. Issue #6.
- [x] **V2-07 — Define backend and primitive strategy** — document evidence-based native/platform/external backend decisions. Issue #7.
- [ ] **V2-08 — Correctness and interoperability regression suite** — expand KAT, invalid-input, serialization and cross-implementation coverage. Issue #8.
- [ ] **V2-09 — Security regression and extended fuzzing** — complete security gates and prolonged fuzz campaigns. Issue #9.
- [ ] **V2-10 — PQC Benchmark Arena performance gate** — demonstrate reproducible v2 improvement and pursue the fastest relevant comparator target. Issue #10.
- [ ] **V2-11 — NEXUS-Q v2.0 Release Candidate** — freeze RC and pass complete release validation. Issue #11.
- [ ] **V2-12 — Freeze and release NEXUS-Q v2.0** — release GitHub artifact first; publish public packages only after individual gates. Issue #12.

## Execution order

`V2-01 → V2-02 → V2-03 → V2-04 → V2-05 → V2-06 → V2-07 → V2-08 → V2-09 → V2-10 → V2-11 → V2-12`

The sequence is intentional: baseline → evidence → optimization → regression/security → external performance gate → release.

## Completion rule

A phase is complete only when:

1. Its GitHub issue acceptance criteria are satisfied.
2. Required tests, benchmarks and security gates are green.
3. Evidence is attached or linked from the issue/PR.
4. The PR is merged into `nexusqv2`.
5. The corresponding checkbox above is changed to `[x]`.

No checkbox is pre-checked merely because the phase was designed.

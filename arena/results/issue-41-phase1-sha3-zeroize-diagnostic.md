# Issue #41 — SHA-3 zeroization A/B diagnostic

**Run:** [PQC Benchmark Arena, commit `140d235`](https://github.com/lecodev-26/nexus-q/actions/runs/37900651695)

**Result:** the hypothesis that SHA-3 `zeroize` explains the observed ML-KEM slowdown is **not supported by this experiment**. Disabling the feature in a temporary, non-production diagnostic build did not yield a consistent latency reduction. Production security settings were not changed.

## Method

- 10 randomized, alternating rounds for V3 with SHA-3 `zeroize` enabled and a diagnostic build with only that feature disabled.
- Same runner source, Rust 1.98.1, GitHub Actions CPU (`INTEL(R) XEON(R) PLATINUM 8573C`), release profile, and workload; 50 iterations and 10 warmups per operation.
- 200 JSONL rows (10 operations per invocation, 20 invocations); CI sample/metadata and matched-round checks passed.
- Cargo.lock SHA-256 reported by both conditions: `665e575808a8b3ad90f483915043fb9d33a469983c8065b93baa63e1354d9da2`.
- Raw evidence: [diagnostic artifact](https://github.com/lecodev-26/nexus-q/actions/runs/37900651695/artifacts/11602841055).

## Paired round results

Ratios are diagnostic-build `zeroize-off` latency divided by `zeroize-on` latency for each matched round. A ratio below 1 means the off build was faster in that pair.

| Operation | On median (ns) | Off median (ns) | Median of 10 paired off/on ratios | Min–max paired ratio |
|---|---:|---:|---:|---:|
| ML-KEM-768 keygen | 49,864.0 | 49,677.5 | 0.99691 (-0.31%) | 0.97179–1.02862 |
| ML-KEM-768 encaps | 43,056.0 | 43,966.5 | 1.01236 (+1.24%) | 0.99034–1.05327 |
| ML-KEM-768 decaps | 52,450.5 | 53,035.5 | 1.00338 (+0.34%) | 0.97748–1.07273 |
| ML-KEM-1024 keygen | 80,792.5 | 80,611.0 | 0.99982 (-0.02%) | 0.96135–1.02579 |
| ML-KEM-1024 encaps | 69,652.5 | 69,508.0 | 0.99173 (-0.83%) | 0.97405–1.07733 |
| ML-KEM-1024 decaps | 80,964.5 | 81,408.0 | 1.00041 (+0.04%) | 0.95070–1.06136 |

## Interpretation and limits

- Three medians are slightly faster with the feature disabled and three are slower; all median effects are within about 1.3%. There is no consistent direction across operations.
- The paired min–max ranges cross 1 for all six operations, and show substantial round-to-round variation relative to the median differences. This is descriptive evidence, not a formal confidence interval.
- Therefore this run does **not** identify SHA-3 `zeroize` as the cause of the earlier ~3–5% ML-KEM differences. It also does not prove the feature has zero cost in every context.
- Do not disable zeroization in production based on this result. Next: run controlled LTO/codegen-units variants with the same V3 source and workload, then document the profile comparison.


## Follow-up: LTO/codegen diagnostic CI attempt (2026-10-09)

- Workflow run: [37901842937](https://github.com/lecodev-26/nexus-q/actions/runs/37901842937).
- The build step for all three profile variants passed. The measurement step failed before the first profile round emitted results, so **no LTO/codegen performance conclusions can be drawn from this run** and no profile artifact was produced.
- Root cause in the workflow harness: CPU feature detection assumed `/proc/cpuinfo` always contains an x86-style `Flags:` field. Linux runners can instead expose `Features:` (for example on ARM) or omit that optional field; with `set -euo pipefail`, the unmatched `grep` terminated the step.
- Correction: parse either `flags` or `Features` in Python and allow an empty feature list when metadata is unavailable. CPU metadata is descriptive only and must not block the benchmark.
- The profile experiment remains pending a successful CI rerun. This is a harness portability failure, not evidence of a cryptographic implementation or benchmark-performance failure.

## Follow-up: second LTO/codegen diagnostic CI attempt (2026-10-09)

- Workflow run: [37902904308](https://github.com/lecodev-26/nexus-q/actions/runs/37902904308).
- All three profile builds and the other benchmark/reference-adapter jobs passed. The profile validator failed because it expected 300 records but received 27; therefore the profile comparison did not produce usable evidence or an artifact.
- The CPU-feature portability correction was effective in allowing the benchmark step to run, but it did not resolve this separate sample-capture/count failure.
- Next harness change: capture each profile invocation to its own temporary JSONL file, assert that each invocation emits exactly 10 records, log the per-invocation count, then append to the aggregate. This should make the point of failure observable instead of only reporting the aggregate count.
- No LTO/codegen performance conclusion is justified yet. Production code and production zeroization settings remain unchanged.

## Follow-up: third LTO/codegen diagnostic CI attempt (2026-10-09)

- Workflow run: [37904007579](https://github.com/lecodev-26/nexus-q/actions/runs/37904007579).
- The per-invocation capture fix worked: all 30 randomized profile invocations emitted exactly 10 JSON records each, for 300 total rows. The validator then failed at its group-count assertion (`AssertionError: 27`), not at sample capture.
- Root cause: the runner emits 10 measurements per invocation but only 9 distinct algorithm/parameter/operation keys. Across three profiles, the correct number of groups is 27 (9 × 3), with 10 observations in each group. The previous assertion incorrectly expected 30 groups.
- Correction: validator now asserts 27 groups and retains the 300-row and 10-observations-per-group checks. Other CI jobs passed; the profile comparison remains unaccepted until this corrected validator runs and the artifact is inspected.
- No profile performance conclusions are drawn from this failed run; production code and zeroization settings are unchanged.
- **Correction in the fourth follow-up below:** this 27-group explanation was incomplete because the grouping key omitted `measurement_method`, merging cached and conventional ML-DSA verification. The correct expected count is 30 groups.


## Follow-up: fourth LTO/codegen diagnostic CI attempt (2026-10-09)

- Workflow run: [37905756222](https://github.com/lecodev-26/nexus-q/actions/runs/37905756222). The 300-row capture completed, but validation still failed; no performance conclusion is accepted.
- Root cause after reviewing the runner rather than only the failing assertion: the runner emits **two ML-DSA `verify` measurements** when `cached-verifier` is enabled: conventional verification and cached-verifier verification. They share algorithm, parameter set and operation, but have different `measurement_method` values. Grouping on only algorithm/parameter/operation merged them, which is why the previous “27 groups” correction was wrong and could not enforce ten samples for every distinct measurement.
- Correct model: 10 distinct measurement types (including both ML-DSA verify methods) × 3 profiles = **30 groups**, each with exactly 10 observations. The validator now includes `measurement_method` in its grouping key and explicitly asserts that both verification methods are present.
- Build profile overrides are now expressed as explicit Cargo `--config profile.release...` arguments instead of environment overrides, so the intended no-LTO and codegen-units=16 settings are visible in the build command. Artifact upload runs even when validation fails, preserving diagnostic evidence.
- These are workflow-harness corrections only. Production cryptographic code and zeroization settings are unchanged. Do not launch the next CI until the local validator and workflow checks pass.

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
- These were workflow-harness corrections only. Production cryptographic code and zeroization settings remained unchanged. The subsequent successful run and its measured results are documented below.


## LTO/codegen diagnostic results — CI run 37906728654 (2026-10-09)

**Status: raw capture and validator passed, but a subsequent profile-configuration audit found that the variants were not named accurately. Do not use this run as a comparison against the repository's production release profile.** The artifact is [available from the PQC Benchmark Arena run](https://github.com/lecodev-26/nexus-q/actions/runs/37906728654/artifacts/11605185482); companion V3 Incremental CI run `37906728626` passed for commit `9947385d970f39b00494e62dd26dd44f7d3273c9`.

Environment: GitHub-hosted `ubuntu-latest`, AMD EPYC 7763 virtualized runner (4 visible CPUs), `rustc 1.98.1 (48a229cea 2026-09-01)`, LLVM 22.1.8. The artifact had 300 JSONL rows, 30 distinct measurement-method/profile groups, and 10 observations per group. Capture and schema/group validation passed.

### Profile-configuration audit and correction

The Arena runner at `arena/runners/nexusq/Cargo.toml` is an independent Cargo workspace (`cargo metadata --no-deps` reports `arena/runners/nexusq` as its `workspace_root`). Therefore, the root `Cargo.toml` `[profile.release]` settings do not automatically apply to this runner. The original workflow's baseline command had no explicit profile overrides; the fresh Termux `cargo build -vv` confirmed the default release invocation used `-C opt-level=3`, `-C embed-bitcode=no`, and `-C strip=debuginfo`, with no Thin-LTO/CGU=1 flags. This is not the repository's intended production profile (`opt-level=3`, Thin LTO, `codegen-units=1`, `panic=abort`, `strip="symbols"`, `debug=false`).

Consequently, the three builds in run `37906728654` should be interpreted as:

- **Standalone default baseline:** Cargo standalone release defaults; effectively no LTO with the default codegen-units count (normally 16), and default panic/strip behavior.
- **`no-lto` variant:** LTO disabled and `codegen-units=1`; this compares codegen-unit count against the default baseline while both are non-LTO.
- **`cgu16` variant:** Thin LTO and `codegen-units=16`; this compares LTO on/off at the default codegen-unit count.

The measurements below remain valid observations of those builds, but the earlier labels and conclusions that called the first build “repository baseline” and treated `cgu16` as an isolated CGU=16 comparison were incorrect. The corrected workflow now pins **all relevant profile settings explicitly** for every build and includes a profile manifest in the artifact. A new CI run is required before drawing production-profile conclusions.

Medians from the original run (variant latency / standalone-default baseline; negative percentages mean faster in this run):

| Measurement | Standalone default median | No LTO, CGU=1 median | No LTO/CGU=1 vs default | Thin LTO, CGU=16 median | Thin LTO/CGU=16 vs default |
|---|---:|---:|---:|---:|---:|
| ML-KEM-768 keygen | 51,125.5 ns | 51,065.5 ns | -0.12% | 48,184.5 ns | -5.75% |
| ML-KEM-768 encaps | 46,747.0 ns | 46,426.5 ns | -0.69% | 43,095.5 ns | -7.81% |
| ML-KEM-768 decaps | 56,014.5 ns | 55,639.0 ns | -0.67% | 52,413.0 ns | -6.43% |
| ML-KEM-1024 keygen | 81,788.0 ns | 80,830.5 ns | -1.17% | 75,806.5 ns | -7.31% |
| ML-KEM-1024 encaps | 72,951.0 ns | 72,571.0 ns | -0.52% | 66,359.0 ns | -9.04% |
| ML-KEM-1024 decaps | 84,808.5 ns | 84,572.5 ns | -0.28% | 78,186.0 ns | -7.81% |
| ML-DSA-65 keygen | 280,994.5 ns | 278,329.5 ns | -0.95% | 282,071.5 ns | +0.38% |
| ML-DSA-65 sign | 623,258.5 ns | 612,713.5 ns | -1.69% | 625,672.5 ns | +0.39% |
| ML-DSA-65 verify (cached key) | 69,936.0 ns | 68,884.0 ns | -1.50% | 70,437.0 ns | +0.72% |
| ML-DSA-65 verify (conventional) | 181,298.5 ns | 178,603.5 ns | -1.49% | 181,724.0 ns | +0.23% |

Median absolute deviations across the 10 observations were calculated from the raw artifact. These results are descriptive measurements from one hosted runner, not a multi-machine benchmark or statistical guarantee.

### Revised interpretation and decision

1. In this original run, enabling Thin LTO at `codegen-units=16` correlated with 5.75–9.04% lower ML-KEM medians than standalone defaults, while ML-DSA measurements were +0.23–0.72% slower. This is not yet a comparison to the production profile.
2. With LTO disabled, changing from the default codegen-unit count to `codegen-units=1` yielded small apparent gains of 0.12–1.69%; this does not establish the effect of CGU count under Thin LTO.
3. **No production-profile decision is supported by this run.** The workflow correction explicitly compares the actual repository release settings against no-LTO/CGU=1 and Thin-LTO/CGU=16, holding opt-level, panic and strip settings constant.
4. Production cryptographic code and zeroization settings remain unchanged. The original run does not resolve all V1/V2/V3 discrepancies and does not justify a universal V3 speedup.

## Corrected production-profile comparison — CI run 37908810902 (2026-10-09)

**Status: all 300 samples validated; results reviewed from the downloaded raw artifact.** The companion [NEXUS-Q V3 Incremental CI](https://github.com/lecodev-26/nexus-q/actions/runs/37908810920) and [PQC Benchmark Arena](https://github.com/lecodev-26/nexus-q/actions/runs/37908810902) runs both succeeded on commit `fdd328675fade5a55a1853daa94640b6a48ae713`. The diagnostic artifact, including raw JSONL, toolchain/CPU metadata, dependency tree and explicit profile manifest, is [available here](https://github.com/lecodev-26/nexus-q/actions/runs/37908810902/artifacts/11606245702).

The three builds now explicitly use these settings, keeping opt-level, panic, strip and debug behavior constant:

- **Production-equivalent baseline:** `opt-level=3`, `lto="thin"`, `codegen-units=1`, `panic="abort"`, `strip="symbols"`, `debug=false`.
- **No LTO:** same settings except `lto=false`.
- **Thin LTO / CGU16:** same settings except `codegen-units=16`.

Environment: GitHub-hosted Ubuntu 24.04, `rustc 1.98.1 (48a229cea 2026-09-01)`, LLVM 22.1.8, 10 randomized alternating rounds per profile. The raw artifact contains 300 rows, 30 measurement-method/profile groups, and exactly 10 samples per group. Numbers below are per-group medians; percentages are relative to the production-equivalent baseline (negative is faster).

| Measurement | Baseline | No LTO / CGU1 | No LTO delta | Thin LTO / CGU16 | CGU16 delta |
|---|---:|---:|---:|---:|---:|
| ML-KEM-768 keygen | 52,113.5 ns | 56,064.0 ns | +7.58% | 53,631.0 ns | +2.91% |
| ML-KEM-768 encaps | 45,063.0 ns | 50,261.0 ns | +11.53% | 46,380.0 ns | +2.92% |
| ML-KEM-768 decaps | 54,652.5 ns | 60,000.0 ns | +9.78% | 56,004.5 ns | +2.47% |
| ML-KEM-1024 keygen | 82,524.0 ns | 88,868.5 ns | +7.69% | 86,130.0 ns | +4.37% |
| ML-KEM-1024 encaps | 69,880.0 ns | 77,902.0 ns | +11.48% | 73,766.0 ns | +5.56% |
| ML-KEM-1024 decaps | 82,433.5 ns | 90,366.0 ns | +9.62% | 86,785.5 ns | +5.28% |
| ML-DSA-65 keygen | 309,896.0 ns | 306,321.0 ns | -1.15% | 312,224.5 ns | +0.75% |
| ML-DSA-65 sign (64-key corpus) | 691,555.0 ns | 690,393.0 ns | -0.17% | 708,350.0 ns | +2.43% |
| ML-DSA-65 verify (cached key) | 74,967.5 ns | 74,732.5 ns | -0.31% | 76,876.0 ns | +2.55% |
| ML-DSA-65 verify (conventional) | 197,807.0 ns | 195,544.0 ns | -1.14% | 201,473.0 ns | +1.85% |

### Interpretation and decision

1. **The previous run's apparent 5.75–9.04% ML-KEM gain does not survive a correct production-profile comparison.** With the repository's actual Thin-LTO/CGU1 settings as baseline, Thin-LTO/CGU16 is slower in all six ML-KEM medians (+2.47% to +5.56%) and all four ML-DSA measurements (+0.75% to +2.55%) on this runner.
2. The no-LTO/CGU1 variant is 7.58–11.53% slower on all six ML-KEM medians, while ML-DSA is between -1.15% and -0.17% (slightly faster). This argues against disabling LTO as a general optimization.
3. **Keep the production release profile unchanged.** These are descriptive medians from one hosted runner and 10 samples per group; they are not a multi-machine confidence interval. Do not infer a universal regression or speedup from this one run.
4. The corrected profile experiment addresses one methodological issue in Phase 1. It does not by itself classify the historical V1/V2/V3 ML-KEM delta. The remaining investigation should inspect generated code and compare like-for-like build artifacts while preserving the existing zeroization/security settings.
5. No production cryptographic implementation or zeroization setting was changed.

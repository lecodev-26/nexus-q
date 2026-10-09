# Issue #41 — V1 vs V3 latency investigation (forensic status)

Date: 2026-10-09
Scope: GitHub Actions run [37909954914](https://github.com/lecodev-26/nexus-q/actions/runs/37909954914), commit `2eecf48bad3e43a31a515fc718093eb3cbe937c1`, PR #42.
Toolchain/workflow: Rust 1.98.1; controlled V1, V1+ML-DSA-zeroize, and V3 runner builds; 10 randomized alternating rounds. Artifacts downloaded to `~/nexusq-issue41-run37909954914/` on the analysis device.

## Executive finding

The data shows a repeatable *observed latency difference* between the V1 reference runner and the V3 runner in this run. It does **not yet establish a single, proven root cause**. The prior narrative that zeroization of SHA-3/SHAKE hashers accounts for roughly 3% of ML-KEM latency is not demonstrated by this experiment: the `V1+zeroize` control only adds the `zeroize` feature to `ml-dsa`; it is not a controlled ML-KEM/SHA3 zeroization on/off comparison. Do not describe that attribution as confirmed until an isolated experiment proves it.

Likewise, the ~9% ML-DSA keygen/verify cost cannot be attributed solely to zeroize based on this dataset: V1+zeroize is a single feature intervention, and V3 differs in code/dependency wiring and runner configuration too. ML-DSA signing medians are close, but the per-round range is wide; “identical performance” would overstate the evidence.

## Artifact inventory and method

- V1: 90 records, 9 operation/method groups.
- V1+zeroize: 90 records, 9 operation/method groups.
- V3: 100 records, 10 operation/method groups. V3 has an additional cached-verifier measurement.
- Each common operation group has 10 round records. Per-round V3/V1 and V1+zeroize/V1 ratios are paired by the round ID parsed from `environment.run_order`.
- The percentages below are medians of the 10 *per-round ratios*. The range is the min/max observed ratio across rounds; it is **not** a 95% confidence interval.
- All times are in nanoseconds; lower is faster. These are descriptive results from one hosted-runner job, not a multi-machine generalization.

## Paired results: V3 vs V1

| Operation | Median paired change | Observed round range |
|---|---:|---:|
| ML-KEM-768 keygen | +4.70% | +1.91% to +7.81% |
| ML-KEM-768 encaps | +4.52% | +0.74% to +8.16% |
| ML-KEM-768 decaps | +2.70% | +0.55% to +8.35% |
| ML-KEM-1024 keygen | +3.91% | +1.37% to +12.52% |
| ML-KEM-1024 encaps | +6.33% | +0.70% to +14.52% |
| ML-KEM-1024 decaps | +5.03% | +1.26% to +12.08% |
| ML-DSA-65 keygen | +6.82% | +2.56% to +10.89% |
| ML-DSA-65 sign (64-key deterministic seed corpus) | -0.76% | -15.43% to -0.03% |
| ML-DSA-65 conventional verify | +6.40% | +3.80% to +7.14% |

The V3 cached-verifier row is a different measurement method and must not be compared as if it were the conventional V1 verification path. Its median in the aggregate artifact is 35,694 ns; conventional V3 verification is 98,539.5 ns. The cached path amortizes verifier construction/precomputation, so label it separately in all reports.

## Paired results: V1+ML-DSA-zeroize vs V1

| Operation | Median paired change | Observed round range |
|---|---:|---:|
| ML-KEM-768 keygen | +1.05% | -2.21% to +4.58% |
| ML-KEM-768 encaps | +1.17% | -4.70% to +3.60% |
| ML-KEM-768 decaps | +0.35% | -3.95% to +2.76% |
| ML-KEM-1024 keygen | -0.63% | -4.84% to +3.30% |
| ML-KEM-1024 encaps | +0.44% | -4.71% to +2.29% |
| ML-KEM-1024 decaps | +0.56% | -4.95% to +1.61% |
| ML-DSA-65 keygen | +7.18% | +2.79% to +7.83% |
| ML-DSA-65 sign | -1.05% | -13.81% to +16.32% |
| ML-DSA-65 conventional verify | +7.88% | +4.37% to +8.67% |

Interpretation: enabling the ML-DSA zeroize feature coincides with a clear keygen/verify latency increase in this particular control, while the ML-KEM deltas are small and noisy. Because the intervention is ML-DSA-only and this is one runner/job, it cannot prove anything about SHA3/SHAKE hasher zeroization inside ML-KEM.

## What differs between V1 and V3

1. The standalone Arena runner is a separate Cargo workspace. Current V3 explicitly patches `ml-kem` and `module-lattice` to the repository's `vendor/` sources; the V1 tag resolves registry dependencies. The workflow includes a dependency-source diagnostic. Vendored source metadata points to upstream revisions, but the actual benchmark still compares different resolution paths and feature/profile contexts; record resolved tree and lockfiles alongside any follow-up run.
2. V3's runner has a `cached-verifier` feature and an additional cached ML-DSA verification operation. This is a distinct API path, not a like-for-like speedup for conventional verify.
3. V3 core code changed from V1 in areas including hybrid KEM constructions, key serialization, and signing wrappers. Those differences should not automatically explain plain ML-KEM primitive measurements; isolate the call path and verify the Arena actually measures the same primitive in both versions.
4. The root release profile is explicitly `opt-level=3`, `lto="thin"`, `codegen-units=1`, `panic="abort"`, `strip="symbols"`, `debug=false`. A previous diagnostic found root profile settings are not inherited by the excluded standalone runner workspace. The corrected LTO/CGU diagnostic builds now specify profiles directly. Keep this distinction visible when comparing builds.

## Conclusions that are and are not supported

Supported:
- In run 37909954914, V3's paired ML-KEM medians are slower than V1 across the six measured operations.
- The V1+ML-DSA-zeroize control has ML-DSA keygen/verify medians about 7–8% slower, while signing medians are close but noisy.
- V3 signing median is close to V1 in this run; the observed per-round range is wide enough that this is not proof of identical performance.
- The existing LTO/CGU diagnostic shows compiler profile choices can have substantial impact, especially on ML-KEM; see `issue-41-phase1-sha3-zeroize-diagnostic.md` and workflow artifacts.

Not established:
- That SHA3/SHAKE hasher zeroization is the cause of the ML-KEM regression.
- That the entire ML-DSA keygen/verify difference is caused exclusively by zeroize.
- That there is one exact “origin” for the full V1-to-V3 delta.
- That these results generalize across CPUs or match AWS-LC/liboqs performance.
- Any statistically rigorous 95% confidence interval from this one job.

## Follow-up plan for Issue #23 (performance kernels)

1. Preserve the current security features. Do not remove zeroize from secret-bearing paths based on these results.
2. Establish a like-for-like baseline: same Rust toolchain, runner source, dependency source/revision, feature set, profile flags, CPU class, and benchmark operation semantics. Archive `cargo tree`, lockfile hashes, `rustc -Vv`, CPU metadata, and exact build commands.
3. For ML-KEM, build a factorial diagnostic that isolates (a) registry vs vendored source, (b) zeroize feature, and (c) profile/LTO/CGU independently. Confirm each variant's actual resolved features with `cargo tree -e features`; do not infer SHA3/SHAKE zeroization effects from the ML-DSA-only control.
4. Capture optimized assembly/disassembly for the same functions in equivalent builds and identify the specific instruction/code-path differences. Keep the benchmark harness outside the timed region except for the operation under test.
5. For Issue #23, prototype architecture-specific kernels (AVX2 on supported x86_64 and NEON on supported AArch64) behind explicit target-feature dispatch with a portable fallback. Require differential tests against the existing Rust implementation, KATs/Wycheproof where applicable, fuzzing, constant-time review, and benchmarks on matching hardware before enabling by default.
6. Run at least three independent Arena jobs on the same runner class; report median, p95, dispersion, and a suitable confidence interval. Do not publish a performance claim based on one hosted runner or on unmatched cached/conventional operations.

## CI / repository status at time of writing

PR #42 is open against `nexusqv3`. The V3 Incremental CI run `37909954886` and PQC Benchmark Arena run `37909954914` completed successfully for commit `2eecf48bad3e43a31a515fc718093eb3cbe937c1`. The Arena's “V2-10 performance evidence” job was skipped, so this run is not evidence that all release gates are satisfied. No merge or issue closure is implied by green workflow status.

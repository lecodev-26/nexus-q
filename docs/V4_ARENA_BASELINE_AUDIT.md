# V4 Arena baseline audit — 2026-10-09

**Scope:** inspect the benchmark documentation and archived Arena artifacts before optimizing kernels for Issue #23. This is a measurement-quality audit, not a new benchmark run and not a claim that the current V4 branch has improved performance.

## Published baseline

`BENCHMARKS.md` records the 2026-10-05 Arena baseline as NEXUS-Q roughly 2.03×–4.46× slower than the best measured comparator across the nine ML-KEM/ML-DSA operations. ML-DSA signing and verification are particularly important targets; the documented largest ratio is ML-DSA-65 signing at 4.46×. These figures are useful as historical prioritization signals, not proof of the exact current gap until the raw artifacts and harness equivalence are revalidated.

## Archived run inspected

Input directory: `artifact-archive/workflow-artifacts/2026-10-09/latest-issue41-run-37918298351/`.

- The NEXUS-Q reference artifact contains 100 JSONL records. The records identify a prior NEXUS-Q revision (`06508e7e84b3b270dd2ca9162220501f91f2a2db`), not the V4 working revision.
- NEXUS-Q records mostly report 50 iterations and 10 warmups, with a separate set of records reporting 320 iterations and 640 warmups. The runner records medians/sample statistics for these measurements.
- The AWS-LC artifact contains six operations: ML-KEM-768 keygen/encaps/decaps and ML-DSA-65 keygen/sign/verify. It does not provide ML-KEM-1024 records in this run.
- AWS-LC reports 20 iterations, 3 warmups, and mean wall-clock latency; the NEXUS-Q records use a median-oriented measurement method and different iteration/warmup settings. The ML-DSA-65 signing records use 320 iterations/640 warmups, and verification is split into cached and conventional cases (which must remain separate).
- The NEXUS-Q environment records a specific Intel Xeon Platinum 8370C CPU and feature set. AWS-LC records the CPU as `github-actions`, without matching CPU-feature metadata. The artifacts therefore do not prove identical hardware/feature conditions.

The archived numbers are useful for triage, not as a fair head-to-head claim. Indicative central values from the records are:

| Operation | NEXUS-Q archived median (µs) | AWS-LC archived mean (µs) |
| --- | ---: | ---: |
| ML-KEM-768 keygen | 50.90 | 12.37 |
| ML-KEM-768 encaps | 44.99 | 12.67 |
| ML-KEM-768 decaps | 54.65 | 15.40 |
| ML-DSA-65 keygen | 271.70 | 41.54 |
| ML-DSA-65 sign | 563.94 | 103.83 |
| ML-DSA-65 verify (conventional; cached excluded) | 168.28 | 34.96 |

These are medians across archived NEXUS-Q per-round medians versus one AWS-LC mean record, not matched statistics on proven-identical hosts. Do **not** treat their quotients as valid speed ratios, acceptance thresholds, or a public leaderboard. They do establish which operations deserve early profiling. The ML-KEM-1024 AWS-LC comparison is missing from this artifact set. Phase 0 must make the runner, primitive layer, host, compiler settings, measurement statistics, warmups, and iteration policy equivalent and verifiable in the same job.

## Phase 0 actions required

1. Prove the Arena runner resolves the exact local source under test using `cargo tree --locked --manifest-path arena/runners/nexusq/Cargo.toml -i ml-kem` and equivalent trees for every relevant dependency. The Arena runner is excluded from the workspace, so the root `[patch.crates-io]` alone is not sufficient evidence; its own manifest must be checked.
2. Ensure NEXUS-Q and each comparator measure the same primitive operation and parameter set. Keep the hybrid ML-KEM-768 + X25519 API benchmark separate from plain FIPS 203 ML-KEM.
3. Run NEXUS-Q and AWS-LC in the same CI job/host where feasible, with pinned source revisions and compiler/build flags. Record CPU model and features for both.
4. Use a common warmup/iteration policy, per-operation samples, median, p95, standard deviation, and explicit measurement method. Target at least 1,000 measured iterations and 100 warmups for the acceptance benchmark.
5. Add AWS-LC ML-KEM-1024 only if the pinned version and adapter expose the required operation with equivalent semantics; otherwise record the coverage limitation and use the best valid comparator available for that operation.
6. Preserve raw JSONL, metadata, run URLs, dependency trees, and generated ratios as PR/Issue evidence. Do not infer causation from one run or combine cached ML-DSA verification with ordinary verification.

## Temporary fuzz policy for V4 development

The `security-ci.yml` workflow now runs its normal Rust security checks and secret scan on `v4/**` pushes and PRs targeting `nexusqv4`. The fuzz harness build retains its previous behavior for pushes to `main` and PRs targeting `main`; all long fuzz soaks remain restricted to pushes to `main`. Thus iterative V4 branch commits and PRs to `nexusqv4` do not run fuzz, while existing main-PR behavior and the four-hour main release/security gates are preserved. Fuzzing is deferred during V4 iteration, not removed from the project. No fuzz target or other workflow is deleted.

## Current status

- [x] Read the documented baseline and inspect the archived 2026-10-09 Arena records.
- [x] Identify the current artifacts' comparability limitations.
- [ ] Repair/prove measurement equivalence and local-source resolution in Phase 0.
- [ ] Re-run the fair baseline before using any ratios as optimization gates.

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

## Dependency provenance confirmed by manifest inspection (2026-10-10)

The standalone runner is explicitly excluded from the root Cargo workspace. Its own `arena/runners/nexusq/Cargo.toml` has local `[patch.crates-io]` entries for `ml-kem` and `module-lattice`, pointing at `vendor/ml-kem` and `vendor/module-lattice`; the root manifest also patches those crates. The standalone runner has its own committed `Cargo.lock`, where patched path packages correctly have no registry `source` field. Existing Rust dependency-info files under the runner's build directory also show a compiled `ml-kem` artifact sourced from `vendor/ml-kem`. These are useful local clues, but CI must emit the resolved dependency trees from the exact locked manifest before this is accepted as reproducible evidence.

Two important limitations remain:

- There is no `crates/nexusq-kernels` or V4 optimized backend yet, so the runner cannot currently prove that it exercises the kernel implementation planned by Issue #23.
- ML-DSA is still resolved from the crates.io `ml-dsa 0.1.1` package; only ML-KEM and `module-lattice` are locally patched. This is not evidence of a local ML-DSA kernel path.
- The runner currently measures ML-KEM-768 and ML-DSA-65 through `nexusq-core` wrappers, but ML-KEM-1024 directly through `ml-kem` types. All three parameter-set groups must be traced and standardized on a semantically equivalent primitive layer before baseline ratios can be considered fair.
- The current NEXUS-Q runner defaults to 50 iterations / 10 warmups for ordinary operations and emits raw per-operation samples plus median, p95, and standard deviation; ML-DSA signing has a separate deterministic 64-key distribution with 5 samples per key. The AWS-LC adapter defaults to 20 iterations / 3 warmups, times each operation as one aggregate interval, and emits only mean latency without raw samples or distribution statistics. The harnesses are therefore not statistically equivalent. Both defaults fall below the Phase 0 acceptance target of at least 1,000 measured samples and 100 warmups; AWS-LC still needs per-operation samples and matching statistics before its results can be compared on matched statistics.
- NEXUS-Q and AWS-LC currently run in separate GitHub Actions jobs. Their metadata does not establish a shared physical/virtual host or matching CPU features.

Accordingly, the dependency manifest configuration is present, but Phase 0 is **not complete**. No kernel-performance claim or fair baseline ratio is approved yet.

## V4 Phase 0 CI evidence — run 38037011873 (2026-10-10)

Artifact: `v4-issue23-phase0-d0787312a4a1a7fd9c5922cb469614aaaa65d4bc` (uploaded by the V4-only workflow).

Observed facts from the artifact:

- The standalone Arena manifest and lockfile hashes were recorded; the run captured Rust/Cargo versions, `uname`, `lscpu`, commit/ref and Cargo metadata.
- `cargo tree --locked --manifest-path arena/runners/nexusq/Cargo.toml -i ml-kem` resolves `ml-kem 0.3.2` from `vendor/ml-kem`.
- The equivalent `module-lattice` tree resolves the local `vendor/module-lattice` source.
- `ml-dsa 0.1.1` still resolves from the registry; this workflow confirms that gap rather than hiding it.
- `crates/nexusq-kernels/Cargo.toml` is absent. The current runner therefore does not yet exercise the planned optimized kernel crate.
- The workflow is a provenance/evidence gate only. A green result is not a benchmark result and does not complete Phase 0.

The artifact was downloaded and inspected from the successful PR run. This evidence supersedes the prior note that CI artifact evidence was pending; all measurement-equivalence items below remain open.

## Phase 0 actions required

1. Prove the Arena runner resolves the exact local source under test using `cargo tree --locked --manifest-path arena/runners/nexusq/Cargo.toml -i ml-kem` and equivalent trees for every relevant dependency. The Arena runner is excluded from the workspace, so the root `[patch.crates-io]` alone is not sufficient evidence; its own manifest must be checked.
2. Ensure NEXUS-Q and each comparator measure the same primitive operation and parameter set. Keep the hybrid ML-KEM-768 + X25519 API benchmark separate from plain FIPS 203 ML-KEM.
3. Run NEXUS-Q and AWS-LC in the same CI job/host where feasible, with pinned source revisions and compiler/build flags. Record CPU model and features for both.
4. Use a common warmup/iteration policy, per-operation samples, median, p95, standard deviation, and explicit measurement method. Target at least 1,000 measured iterations and 100 warmups for the acceptance benchmark.
5. Add AWS-LC ML-KEM-1024 only if the pinned version and adapter expose the required operation with equivalent semantics; otherwise record the coverage limitation and use the best valid comparator available for that operation.
6. Preserve raw JSONL, metadata, run URLs, dependency trees, and generated ratios as PR/Issue evidence. Do not infer causation from one run or combine cached ML-DSA verification with ordinary verification.

## V4-only CI policy (restarted 2026-10-10)

V4 has its own lightweight workflow, `.github/workflows/v4-issue23-phase0.yml`, with the same file/configuration on `nexusqv4` and `v4/issue-23-kernel-work`. It triggers on PR updates targeting `nexusqv4` only when the PR head is `v4/issue-23-kernel-work`, or on manual dispatch from either exact V4 ref. It intentionally has no `push` trigger, avoiding duplicate push-plus-PR runs. Concurrency is scoped to the ref or PR and cancels superseded runs within that V4 work item. It captures toolchain/host metadata, locked dependency trees for ML-KEM, module-lattice and ML-DSA, Cargo metadata, patch paths and kernel-crate readiness as an artifact. It deliberately does not run workspace tests, fuzz soaks, SDK jobs, release jobs or benchmarks from other version lines. Do not add V4 to global `main` security/release workflows as a shortcut.

## Current status

- [x] Read the documented baseline and inspect the archived 2026-10-09 Arena records.
- [x] Identify the current artifacts' comparability limitations.
- [ ] Repair/prove measurement equivalence and local-source resolution in Phase 0.
- [x] Add a V4-only Phase 0 provenance workflow and collect its first artifact: [run 38037011873](https://github.com/lecodev-26/nexus-q/actions/runs/38037011873).
- [ ] Re-run the fair baseline before using any ratios as optimization gates.

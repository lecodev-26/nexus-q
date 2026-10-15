# Native Assembly Implementation Checklist

Tracking issue: [#48](https://github.com/lecodev-26/nexus-q/issues/48).

A task may be checked only when its evidence is linked. A successful compile alone does not complete an optimization task. Status keys: `[ ]` pending, `[~]` in progress, `[!]` blocked, `[x]` verified complete.

## P0 — Repository and historical inventory

- [x] `NQ-001` Confirm clean worktree and record base commit, branch and remote refs. Evidence: `docs/performance/HISTORICAL_DECISIONS.md`.
- [x] `NQ-002` Compare main, nexusqv4, PR #46 and PR #47 file-by-file. Evidence: `docs/performance/FILE_MIGRATION_MATRIX.md`.
- [x] `NQ-003` Classify changed files as keep, adapt, historical or reject. Evidence: `docs/performance/FILE_MIGRATION_MATRIX.md`.
- [x] `NQ-004` Verify archive manifests and SHA-256 hashes for retained artifacts. Verified 392 files across 28 V4 measurement/Phase 0 run manifests from PR #46; all Git blob hashes matched.
- [x] `NQ-005` Identify deleted workflows and ensure repository-wide gates are preserved. The new branch is additive; existing workflows remain intact. Evidence: `.github/workflows/native-assembly-ci.yml`.
- [ ] `NQ-006` Inventory current production callsites for all nine operations.
- [ ] `NQ-007` Record dependency versions and vendored-source provenance.
- [x] `NQ-008` Confirm README and active docs distinguish current state from history. Evidence: `README.md` and `docs/performance/HISTORICAL_DECISIONS.md`.

## P1 — New line and project documentation

- [x] `NQ-009` Create issue #48 and cross-link the historical issue. Evidence: [Issue #48](https://github.com/lecodev-26/nexus-q/issues/48) links #23, #46 and #47.
- [x] `NQ-010` Create a dedicated branch from the selected stable base. Evidence: `perf/issue-48-native-assembly-gate`, based on `nexusqv4` commit `dc560e0`.
- [x] `NQ-011` Create a dedicated PR and link issue #48. Evidence: [draft PR #49](https://github.com/lecodev-26/nexus-q/pull/49).
- [x] `NQ-012` Add ROADMAP.md with phase exit criteria. Evidence: `docs/performance/ROADMAP.md`.
- [x] `NQ-013` Add IMPLEMENTATION_CHECKLIST.md with stable task IDs. Evidence: 110 IDs in `docs/performance/IMPLEMENTATION_CHECKLIST.md`.
- [x] `NQ-014` Add BENCHMARK_BASELINE.md with raw-evidence references. Evidence: `docs/performance/BENCHMARK_BASELINE.md`.
- [x] `NQ-015` Add CORRECTNESS_AND_SECURITY.md with blocking requirements. Evidence: `docs/performance/CORRECTNESS_AND_SECURITY.md`.
- [x] `NQ-016` Add HISTORICAL_DECISIONS.md and preserve prior audit documents under `docs/performance/history/`.
- [x] `NQ-017` Update README performance status without claiming a pass. Evidence: V4 status section in `README.md`.
- [ ] `NQ-018` Update changelog only when real implementation changes exist.

## P2 — CI and benchmark contract

- [x] `NQ-019` Add a fast Rust validation workflow for the new branch/PR. Evidence: [CI run #2](https://github.com/lecodev-26/nexus-q/actions/runs/38725627171): format, check, Clippy, tests, AVX2 differential tests, runner check and build pass; rustdoc fails on a redundant link, now corrected for rerun.
- [x] `NQ-020` Add an unsafe-code policy check for the kernel boundary. Evidence: [CI run #2](https://github.com/lecodev-26/nexus-q/actions/runs/38725627171), unsafe-code boundary job passes.
- [x] `NQ-021` Keep existing security, fuzz, SDK and release workflows intact. No legacy workflow deletions were imported.
- [x] `NQ-022` Pin the AWS-LC commit and record its build configuration in `.github/workflows/native-assembly-benchmarks.yml`.
- [x] `NQ-023` Pin the CI channel to stable and record rustc/cargo versions in both native assembly workflows.
- [x] `NQ-024` Ensure the benchmark is configured to use the branch's path-patched vendored ML-KEM/ML-DSA and `experimental-kernels` feature; CI run #2 confirms the runner builds; benchmark execution failed before measurements because cargo run did not select a binary, now corrected for rerun.
- [x] `NQ-025` The runner and evaluator define all nine required operations; benchmark run #2 failed before producing operation samples because cargo run did not select a binary; corrected for rerun.
- [x] `NQ-026` Configure 100 warmups and 1000 measured samples (ML-DSA sign uses 1024 seeded samples) in the benchmark workflow.
- [x] `NQ-027` Preserve raw `samples_ns` in each JSONL result and upload all round files as CI artifacts.
- [x] `NQ-028` Compute median, nearest-rank p95 and population standard deviation from pooled raw samples in `arena/scripts/evaluate_native_assembly_gate.py`.
- [x] `NQ-029` Capture CPU/toolchain/revision/lock hash and per-row CPU features in the benchmark workflow.
- [ ] `NQ-030` Review wrapper/context overhead for every comparator operation.
- [x] `NQ-031` Configure three rounds with alternating NEXUS-Q/AWS-LC suite order.
- [x] `NQ-032` Evaluator fails closed on missing operations, duplicate rows, invalid samples or fewer than 1000 samples.
- [x] `NQ-033` Configure upload of raw JSONL, gate report and host/toolchain metadata; CI run #2 uploaded an artifact, but it contains only partial metadata because the benchmark command failed before sampling.

## P3 — ML-KEM basemul and accumulation

- [ ] `NQ-034` Write scalar oracle tests for all 128 basemul pairs.
- [ ] `NQ-035` Document coefficient bounds for input and output representations.
- [ ] `NQ-036` Prove the gamma-times-coefficient intermediate reduction bound.
- [ ] `NQ-037` Prove the product and accumulation bounds fit the selected lane width.
- [ ] `NQ-038` Design the AVX2 assembly ABI and register/clobber contract.
- [ ] `NQ-039` Implement AVX2 basemul assembly with documented preconditions.
- [ ] `NQ-040` Implement fused/vector accumulation in native assembly.
- [ ] `NQ-041` Add boundary coefficient and adversarial input tests.
- [ ] `NQ-042` Add randomized differential tests against scalar oracle.
- [ ] `NQ-043` Add explicit scalar-forcing tests and runtime dispatch tests.
- [ ] `NQ-044` Wire assembly into the real vendor ML-KEM production callsite.
- [ ] `NQ-045` Inspect generated object/disassembly to prove the native path exists.
- [ ] `NQ-046` Measure microkernel latency and end-to-end operation latency.
- [ ] `NQ-047` Record correctness and benchmark evidence in the checklist.

## P4 — ML-KEM NTT and modular arithmetic

- [ ] `NQ-048` Audit the existing AVX2 forward NTT and its production callsite.
- [ ] `NQ-049` Audit the existing AVX2 inverse NTT and its production callsite.
- [ ] `NQ-050` Write range proofs for every multiply, accumulation and reduction stage.
- [ ] `NQ-051` Implement/tune assembly NTT stages with an explicit lane layout.
- [ ] `NQ-052` Implement/tune assembly inverse NTT stages and normalization.
- [ ] `NQ-053` Validate zeta ordering and pair/lane permutation invariants.
- [ ] `NQ-054` Differential-test random and boundary polynomials.
- [ ] `NQ-055` Test fallback behavior on CPUs without AVX2.
- [ ] `NQ-056` Benchmark NTT/inverse NTT in isolation and in full operations.
- [ ] `NQ-057` Check for spills, redundant copies and transition penalties.

## P5 — ML-KEM full operation paths

- [ ] `NQ-058` Profile ML-KEM-768 key generation after basemul/NTT integration.
- [ ] `NQ-059` Profile ML-KEM-768 encapsulation after integration.
- [ ] `NQ-060` Profile ML-KEM-768 decapsulation after integration.
- [ ] `NQ-061` Profile ML-KEM-1024 key generation after integration.
- [ ] `NQ-062` Profile ML-KEM-1024 encapsulation after integration.
- [ ] `NQ-063` Profile ML-KEM-1024 decapsulation after integration.
- [ ] `NQ-064` Inspect SampleNTT, CBD, SHAKE and packing hotspots.
- [ ] `NQ-065` Optimize only hotspots supported by repeatable measurements.
- [ ] `NQ-066` Verify Fujisaki–Okamoto comparison/select path remains constant-time.
- [ ] `NQ-067` Check secret buffer lifetimes and zeroization.
- [ ] `NQ-068` Confirm all six KEM operations remain byte/API compatible.

## P6 — ML-DSA native arithmetic

- [ ] `NQ-069` Create/verify scalar ML-DSA arithmetic oracle and test vectors.
- [ ] `NQ-070` Document q=8380417 bounds separately from ML-KEM arithmetic.
- [ ] `NQ-071` Prove 32-bit/64-bit intermediate bounds for assembly multiplication.
- [ ] `NQ-072` Design AVX2 assembly NTT lane layout and register contract.
- [ ] `NQ-073` Implement/tune ML-DSA forward NTT assembly.
- [ ] `NQ-074` Implement/tune ML-DSA inverse NTT assembly.
- [ ] `NQ-075` Implement pointwise multiplication and vector-dot accumulation assembly.
- [ ] `NQ-076` Add reduction, freeze and conditional-add correctness tests.
- [ ] `NQ-077` Add boundary and randomized differential tests.
- [ ] `NQ-078` Wire assembly into real ML-DSA callsites.
- [ ] `NQ-079` Inspect disassembly and runtime feature dispatch.
- [ ] `NQ-080` Measure arithmetic kernels and complete operations.

## P7 — ML-DSA full operation paths

- [ ] `NQ-081` Profile ML-DSA-65 key generation end-to-end.
- [ ] `NQ-082` Profile ML-DSA-65 signing end-to-end.
- [ ] `NQ-083` Profile ML-DSA-65 verification end-to-end.
- [ ] `NQ-084` Inspect rejection sampling and signing-loop cost.
- [ ] `NQ-085` Inspect packing, hints, decomposition and norm checks.
- [ ] `NQ-086` Inspect SHAKE, matrix expansion and copies/allocations.
- [ ] `NQ-087` Optimize additional assembly kernels only with profiling evidence.
- [ ] `NQ-088` Preserve signing rejection semantics and constant-time behavior.
- [ ] `NQ-089` Run malformed signature/key and invalid input tests.
- [ ] `NQ-090` Confirm all three DSA operations remain API/encoding compatible.

## P8 — Security, fallback and portability

- [ ] `NQ-091` Review every unsafe block and assembly routine.
- [ ] `NQ-092` Check ABI, stack alignment, register clobbers and unwind assumptions.
- [ ] `NQ-093` Check unsupported CPUs never execute unsupported instructions.
- [ ] `NQ-094` Run forced-scalar correctness suite.
- [ ] `NQ-095` Run NIST known-answer vectors for supported parameter sets.
- [ ] `NQ-096` Run differential corpus against RustCrypto/reference backend.
- [ ] `NQ-097` Run fuzz/sanitizer jobs where supported by CI runners.
- [ ] `NQ-098` Review timing leakage risks and secret-dependent control flow.
- [ ] `NQ-099` Review zeroization and temporary/spilled secret lifetimes.
- [ ] `NQ-100` Record limitations where a security test cannot be automated.

## P9 — Gate, evidence and closure

- [ ] `NQ-101` Run at least three controlled full-suite benchmark rounds.
- [ ] `NQ-102` Check median ratio <=1.5x for every required operation.
- [ ] `NQ-103` Check p95 ratio <=1.5x for every required operation.
- [ ] `NQ-104` Fail the gate if any operation or statistic is missing.
- [ ] `NQ-105` Confirm no operation was removed or gate threshold changed.
- [ ] `NQ-106` Compare results against the archived baseline with metadata.
- [ ] `NQ-107` Upload raw samples, summary, CPU/toolchain and commit metadata.
- [ ] `NQ-108` Update README and BENCHMARKS.md with the exact accepted evidence.
- [ ] `NQ-109` Ensure every checklist item links to tests, code or CI evidence.
- [ ] `NQ-110` Complete final review and leave package/release publication separate.

**Initial checklist size:** 110 tasks. Split or add tasks when implementation details require it; do not manufacture completion to meet a count.

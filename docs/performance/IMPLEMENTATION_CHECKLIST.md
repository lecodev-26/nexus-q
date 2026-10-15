# Native Assembly Implementation Checklist

Tracking issue: [#48](https://github.com/lecodev-26/nexus-q/issues/48).

A task may be checked only when its evidence is linked. A successful compile alone does not complete an optimization task. Status keys: `[ ]` pending, `[~]` in progress, `[!]` blocked, `[x]` verified complete.

## P0 — Repository and historical inventory

- [ ] `NQ-001` Confirm clean worktree and record base commit, branch and remote refs.
- [ ] `NQ-002` Compare main, nexusqv4, PR #46 and PR #47 file-by-file.
- [ ] `NQ-003` Classify changed files as keep, adapt, historical or reject.
- [ ] `NQ-004` Verify archive manifests and SHA-256 hashes for retained artifacts.
- [ ] `NQ-005` Identify deleted workflows and ensure repository-wide gates are preserved.
- [ ] `NQ-006` Inventory current production callsites for all nine operations.
- [ ] `NQ-007` Record dependency versions and vendored-source provenance.
- [ ] `NQ-008` Confirm README and active docs distinguish current state from history.

## P1 — New line and project documentation

- [ ] `NQ-009` Create issue #48 and cross-link the historical issue.
- [ ] `NQ-010` Create a dedicated branch from the selected stable base.
- [ ] `NQ-011` Create a dedicated PR and link issue #48.
- [ ] `NQ-012` Add ROADMAP.md with phase exit criteria.
- [ ] `NQ-013` Add IMPLEMENTATION_CHECKLIST.md with stable task IDs.
- [ ] `NQ-014` Add BENCHMARK_BASELINE.md with raw-evidence references.
- [ ] `NQ-015` Add CORRECTNESS_AND_SECURITY.md with blocking requirements.
- [ ] `NQ-016` Add HISTORICAL_DECISIONS.md and preserve prior audit documents.
- [ ] `NQ-017` Update README performance status without claiming a pass.
- [ ] `NQ-018` Update changelog only when real implementation changes exist.

## P2 — CI and benchmark contract

- [ ] `NQ-019` Add a fast Rust validation workflow for the new branch/PR.
- [ ] `NQ-020` Add an unsafe-code policy check for the kernel boundary.
- [ ] `NQ-021` Keep existing security, fuzz, SDK and release workflows intact.
- [ ] `NQ-022` Pin the AWS-LC commit and record its build configuration.
- [ ] `NQ-023` Pin Rust toolchain and record rustc/cargo versions.
- [ ] `NQ-024` Ensure the benchmark measures the actual local production code.
- [ ] `NQ-025` Ensure all nine required operations are present.
- [ ] `NQ-026` Use 100 warmups and 1000 measured operations per operation.
- [ ] `NQ-027` Preserve raw per-operation latency samples.
- [ ] `NQ-028` Compute median, p95 and dispersion from raw samples.
- [ ] `NQ-029` Record CPU model/features, OS, flags, revision and lockfile hash.
- [ ] `NQ-030` Review wrapper/context overhead for every comparator operation.
- [ ] `NQ-031` Alternate suite order or use repeated paired rounds where feasible.
- [ ] `NQ-032` Fail if any required operation or comparator result is missing.
- [ ] `NQ-033` Upload JSONL, summary report, metadata and toolchain artifacts.

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

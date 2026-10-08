# NEXUS-Q v2 — V2-01 Benchmark Baseline

Status: **locked for V2 optimization work**

V2-01 establishes the reproducible performance reference used by V2-02 through V2-10. It does not claim platform-wide performance or superiority.

## Locked workload

The V2 optimization target is the nine-operation NEXUS-Q PQC matrix:

| Algorithm | Parameter set | Operations |
| --- | --- | --- |
| ML-KEM | 768 | keygen, encaps, decaps |
| ML-KEM | 1024 | keygen, encaps, decaps |
| ML-DSA | 65 | keygen, sign, verify |

The canonical implementation is `arena/runners/nexusq`. It uses:

- 20 measurement iterations
- 3 warmups
- `std::time::Instant`
- mean wall-clock latency in ns/op
- release/optimized build
- normalized JSONL output
- the Arena v1 schema and workload shape

The runner source is intentionally reused rather than creating a second benchmark implementation. This prevents V2 from silently changing the workload while optimizing it.

## v1 locked reference

The final v1 PQC Benchmark Arena run used the same nine NEXUS-Q workloads on x86_64 Linux CI:

| Operation | v1 NEXUS-Q |
| --- | ---: |
| ML-KEM-768 keygen | 33.94 µs |
| ML-KEM-768 encaps | 27.97 µs |
| ML-KEM-768 decaps | 34.62 µs |
| ML-KEM-1024 keygen | 53.89 µs |
| ML-KEM-1024 encaps | 46.05 µs |
| ML-KEM-1024 decaps | 52.14 µs |
| ML-DSA-65 keygen | 168.69 µs |
| ML-DSA-65 sign | 600.73 µs |
| ML-DSA-65 verify | 101.20 µs |

These are the V2 optimization reference numbers. Lower latency is better.

The complete v1 external comparison and pinned implementations remain documented in `BENCHMARKS.md`. The final Arena run validated 57 normalized measurements across eight implementations.

## Local/Termux role

A local run is useful for fast feedback and profiling, but it is **not** a replacement for the Arena reference environment.

V2-01 local evidence was generated on the Android/Termux development environment from the exact Arena reference runner:

- ML-KEM-768: 143612 / 128769 / 155196 ns
- ML-KEM-1024: 210892 / 262323 / 235104 ns
- ML-DSA-65: 891565 / 561135 / 494815 ns

These values are recorded only as local evidence. They must not be compared numerically with the x86_64 CI v1 reference because the CPU, OS and execution environment differ.

Raw local evidence: `artifacts/v2/v2-01/nexusq-local.jsonl`

## CI role

`.github/workflows/v2-benchmark-baseline.yml` provides an explicit `workflow_dispatch` gate that:

1. records toolchain/CPU/commit metadata;
2. builds the canonical Arena NEXUS-Q runner in release mode;
3. executes exactly the nine locked operations;
4. verifies 20 iterations and 3 warmups;
5. validates the normalized operation matrix;
6. retains the JSONL and environment metadata as a GitHub Actions artifact.

This workflow is intentionally separate from the normal V2 PR CI so baseline measurement is reproducible without running a benchmark on every code change.

## V2 regression rule

The v1 values above remain the locked historical optimization reference. For the authoritative V2-10 gate, the workflow checks out `v1.0.0`, applies the V2 `ml-dsa` `zeroize` dependency feature to the V1 reference build, and executes the same nine-operation runner on the same GitHub-hosted runner class as the V2 measurement. The hardening overlay isolates V2 implementation changes from the deliberate cryptographic dependency-hardening cost; the historical plain-V1 measurements remain separate evidence and are not silently substituted. A retained performance change must still show a reproducible improvement under the same benchmark conditions.

V2-10 remains the authoritative external performance gate. No performance-leadership claim is made before that gate.

## Evidence

- v1 reference: `BENCHMARKS.md`
- canonical runner: `arena/runners/nexusq/src/main.rs`
- local V2-01 JSONL: `artifacts/v2/v2-01/nexusq-local.jsonl`
- CI baseline workflow: `.github/workflows/v2-benchmark-baseline.yml`

## V2-10 performance gate

The authoritative V2-10 performance evidence compares V1 and V2 using the same benchmark harness on the same GitHub Actions runner. The current harness executes five alternating V1/V2 rounds with 50 measurement iterations and 10 warmups per operation.

Recorded acceptance criteria (non-blocking for frozen V2):
- geometric mean V2/V1 <= 0.95;
- no individual operation may regress by more than 5%;
- the former 5-of-9 improvement rule is diagnostic only, not an acceptance criterion;
- complete normalized coverage and retained raw artifacts are required.

The former 5-of-9 rule was introduced by V2-10 itself in commit ff53b82 and was not part of V2-01 through V2-09 or the frozen V1 Arena protocol. It is retained as historical process evidence, not as a release gate.

The V1 reference uses the V2 security-equivalent ml-dsa/zeroize dependency feature and the current Arena runner harness, so the comparison isolates V2 implementation changes from that deliberate hardening cost.

### Final V2 performance evidence

GitHub Actions run 37815114581, commit 7ab06e4:
- V1/V2 reference benchmark: PASS
- V1 measurements: 45
- V2 measurements: 45
- external comparator adapters: PASS
- normalized matrix: 138 rows
- benchmark artifacts: uploaded

Latest aggregate:
- geometric mean V2/V1: 1.0647513576 (6.48% slower) — FAIL
- individual regression >5%: yes — FAIL
- operations improved >=5%: 0/9 — diagnostic only

The immediately preceding corrected run 37811914420 produced V2/V1 = 0.885 with no individual regression above 5%. The contrast means V2 does not claim a validated performance improvement and does not claim that the latest regression is a stable V2-wide regression.

See docs/V2_PERFORMANCE_RESULTS.md for the full comparison and artifact record. The evidence job is intentionally non-blocking for the frozen V2 release: a NOT_MET performance result is recorded honestly rather than hidden or converted into a code change.

Evidence run: https://github.com/lecodev-26/nexus-q/actions/runs/37815114581

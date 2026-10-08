# NEXUS-Q v2 — V2-02 Hotspot Profile

Status: **profile baseline established; optimization work is deferred to V2-03/V2-04**.

V2-02 is an evidence-gathering phase. No cryptographic implementation was changed for speed in this phase.

## Profile harness

`arena/runners/nexusq/src/bin/profile_hotspots.rs` executes the exact nine V2 target workloads used by the Arena runner, with 2,000 measured iterations and 20 warmups.

The harness records:

- latency per operation;
- allocation count per operation;
- reallocation count per operation;
- allocated/deallocated bytes per operation.

For CPU callgraphs, `.github/workflows/v2-profile-hotspots.yml` uses Linux `perf` with the `cpu-clock` software event and retains `perf.data`, `perf report`, and `perf script` artifacts. This avoids treating Android/Termux profiling restrictions as a project defect.

## Local quantitative profile

The local run was performed with the same profiling harness on the Android/Termux development environment. Values are not comparable to the x86_64 Arena numbers as absolute performance measurements; they are useful for hotspot ranking and allocation behavior.

| Workload | ns/op | allocs/op | allocated bytes/op |
| --- | ---: | ---: | ---: |
| ML-KEM-768 keygen | 148,788.9 | 5.00 | 4,736 |
| ML-KEM-768 encaps | 142,615.8 | 1.00 | 1,088 |
| ML-KEM-768 decaps | 166,872.6 | 0.00 | 0 |
| ML-KEM-1024 keygen | 240,166.5 | 5.00 | 6,272 |
| ML-KEM-1024 encaps | 231,501.2 | 0.00 | 0 |
| ML-KEM-1024 decaps | 261,608.0 | 0.00 | 0 |
| ML-DSA-65 keygen | 895,151.7 | 4.00 | 108,768 |
| ML-DSA-65 sign | 809,402.5 | 3.00 | 13,549 |
| ML-DSA-65 verify | 535,778.3 | 3.00 | 48,192 |

The complete raw local table is retained in `artifacts/v2/v2-02/local-profile.tsv`.

## Hotspot ranking

The local profile establishes the first optimization priority:

1. **ML-DSA-65 keygen** — highest measured latency and significant allocation traffic.
2. **ML-DSA-65 sign** — second-highest latency; repeated allocations are present.
3. **ML-DSA-65 verify** — third-highest latency; parsing/verification path allocates materially more than ML-KEM operations.
4. **ML-KEM-1024 decaps/encaps/keygen** — next ML-KEM cost tier, with zero per-operation heap allocation in this harness.
5. **ML-KEM-768 operations** — lower cost overall; encaps has one observable output allocation while decapsulation has none.

These are hotspot priorities, not proof of which internal primitive consumes the CPU. V2-03/V2-04 must use the Linux CPU callgraphs to identify the actual NTT, polynomial arithmetic, sampling, hashing and data-movement costs before changing implementation code.

## Allocation findings

The measured heap behavior rules out a blanket allocation optimization as the first move for ML-KEM-1024: all three target operations measured zero heap allocations per operation in the harness.

ML-DSA sign/verify and ML-KEM-768 encaps do show measurable output/parsing allocation traffic. The source paths include serialization/parsing boundaries, so these are candidates for V2-04/V2-05 only if a retained change demonstrates a reproducible benefit without weakening zeroization or correctness.

## Termux profiling limitation

Android's `simpleperf` refused the local callgraph capture because the device's `security.perf_harden` policy cannot be changed from the authorized Termux context. This is an environment limitation, not a NEXUS-Q failure. The phase therefore uses the dedicated Linux CI workflow for CPU callgraphs and keeps the local allocation/latency profile as supporting evidence.

## Optimization map

- **V2-03 ML-KEM:** inspect NTT/INTT, polynomial arithmetic, modular reduction, sampling/hashing and data movement in ML-KEM-768/1024, starting from the Linux callgraphs.
- **V2-04 ML-DSA:** inspect NTT/INTT, polynomial arithmetic, sampling, hashing and rejection loops, with keygen/sign/verify prioritized in that order by the local cost profile.
- **V2-05 memory:** revisit the measured ML-DSA allocation sites and ML-KEM-768 encaps output allocation only after CPU hotspots are understood.
- No optimization is retained from this phase alone.

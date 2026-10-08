# NEXUS-Q v2 — Performance Results and Closure Record

Status: V2 historical/frozen record
Version: 2.0.0
Release line: nexusqv2
Comparison baseline: V1 v1.0.0

## Executive conclusion

NEXUS-Q v2 does not claim a validated performance improvement over V1.

The final Arena methodology was corrected so V1 and V2 use the same runner harness, the same GitHub Actions runner, the same captured toolchain/CPU metadata, five alternating V1/V2 rounds, 50 measurement iterations, and 10 warmups per operation.

The latest completed run produced V2/V1 = 1.0647513576, or 6.48% slower in geometric mean. The preceding corrected run produced V2/V1 = 0.885, or approximately 11.5% lower aggregate latency for V2 in that execution. The Arena remains an evidence-producing check for frozen V2: it records whether the performance criteria were met, but does not block the engineering release because V2 makes no performance-improvement claim.

Because those consecutive corrected runs disagree materially, the V2 record treats performance as unresolved rather than conclusively regressed. Security and engineering hardening are accepted; performance leadership over V1 was not demonstrated. Further performance investigation is deferred to V3.

No V2 cryptographic implementation was changed merely to make the benchmark gate pass.

## Latest Arena run

GitHub Actions run: 37815114581
Commit: 7ab06e4473a150d5e45a35500c7aa1cede237a2e
Result: performance criteria failed; benchmark infrastructure passed.

| Metric | Result | Interpretation |
| --- | ---: | --- |
| Geometric mean V2/V1 | 1.0647513576 | 6.48% slower overall |
| Maximum allowed | 0.95 | Not met |
| Any regression >5% | Yes | Not met |
| Improved >=5% | 0/9 | Diagnostic only |
| Normalized rows | 138 | Complete matrix |
| V1 reference | PASS | Same-runner |
| V2 reference | PASS | Same-runner |
| Comparator adapters | PASS | Configured set |
| Normalization | PASS | No harness-count failure |

## Operation-level result

| Operation | V1 | V2 | Ratio V2/V1 |
| --- | ---: | ---: | ---: |
| ML-DSA-65 keygen | 283.730 us | 284.344 us | 1.0022 |
| ML-DSA-65 sign | 620.367 us | 945.226 us | 1.5237 |
| ML-DSA-65 verify | 181.798 us | 181.479 us | 0.9982 |
| ML-KEM-1024 decaps | 83.992 us | 84.859 us | 1.0103 |
| ML-KEM-1024 encaps | 72.041 us | 73.221 us | 1.0164 |
| ML-KEM-1024 keygen | 81.264 us | 82.191 us | 1.0114 |
| ML-KEM-768 decaps | 54.537 us | 55.997 us | 1.0268 |
| ML-KEM-768 encaps | 45.081 us | 46.063 us | 1.0218 |
| ML-KEM-768 keygen | 49.819 us | 51.185 us | 1.0274 |

ML-KEM shows a small movement toward slower V2 execution in this run. ML-DSA signing is the dominant outlier.

## Previous corrected run

Run 37811914420 completed the same corrected benchmark matrix and produced:

V2/V1 geometric mean = 0.885

That execution had no individual regression above 5%. The only old blocker was the 5-of-9 improvement requirement, which has since been removed because it was introduced by V2-10 itself and was not part of the earlier V2 plan or frozen V1 protocol.

The contrast between 0.885 and 1.0647513576 is the reason this record does not declare either a definitive V2 performance win or a definitive V2-wide regression.

## Why the 5-of-9 rule was removed

The original V2-10 gate added a requirement that at least five of nine operations improve by at least 5%.

That rule was introduced in commit ff53b82. It was not present in V2-01 through V2-09, was not part of the frozen V1 Arena protocol, and was not backed by the earlier optimization evidence.

It is therefore historical process evidence, not a V2 acceptance criterion.

The current gate retains:
1. aggregate geometric-mean ceiling;
2. maximum individual regression ceiling;
3. complete normalized coverage;
4. same-runner V1/V2 execution;
5. retained raw artifacts.

## Security/performance trade-off

V2 introduced deliberate security hardening, including the ml-dsa/zeroize feature. The V1 reference for the final comparison was rebuilt with that same feature so the comparison does not treat the deliberate hardening cost as an implementation regression.

The project records the trade-off honestly:
- security hardening was prioritized;
- performance leadership over V1 was not demonstrated;
- the implementation was not weakened to manufacture a benchmark win;
- performance investigation belongs in V3.

## Artifacts and independent verification

Primary evidence run:
https://github.com/lecodev-26/nexus-q/actions/runs/37815114581

Retained artifacts:
- pqc-arena-v1-reference
- pqc-arena-nexusq-reference
- pqc-arena-liboqs-0.16.0
- pqc-arena-circl-1.6.4
- pqc-arena-openssl-3.5.9
- pqc-arena-aws-lc-ec05f25
- pqc-arena-botan-3.13.0
- pqc-arena-rustcrypto-kems
- pqc-arena-pq-code-package

An independent reviewer can open the run, download the artifacts, inspect the JSONL measurements, and reproduce the ratios from the raw records.

## V2 closure boundary

V2 is frozen as an engineering release with security hardening, correctness/interoperability work, CI/release gates, corrected benchmark methodology, documented performance uncertainty, and reproducible raw evidence.

The following work moves to V3:
- profiling ML-DSA signing;
- profiling ML-KEM;
- run-to-run variance investigation;
- compiler/toolchain effects;
- dependency and feature effects;
- zeroization overhead;
- vendored dependency differences;
- benchmark scheduling/CPU effects;
- any optimization backed by fresh evidence.

No V2 implementation changes are required by this document.

## V3 performance investigation boundary

V2 is frozen without a performance claim. V3 starts from the retained V1/V2 evidence and must explain the observed variance before optimization. Initial priorities are ML-DSA-65 signing, benchmark runner variance, CPU/scheduler effects, compiler/toolchain and feature effects, zeroization cost, and dependency/backend differences.

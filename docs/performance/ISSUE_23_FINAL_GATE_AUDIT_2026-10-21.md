# Issue #23 — final 1.00× gate audit

**Date:** 2026-10-21  
**Evidence source:** Native Backend Gate run [39050671654](https://github.com/lecodev-26/nexus-q/actions/runs/39050671654), six hosted-runner replicas; raw JSONL artifacts downloaded and re-evaluated with the original three official rounds per replica.  
**Measured revision:** `8a29d2ce41aea60481ed2455227d70017038a4c9`

## Result

The official 1.5× median-and-p95 gate is the current intermediate gate. Re-evaluating the same raw samples with the original Issue #23 final requirement (`median <= 1.00×` **and** `p95 <= 1.00×` for every operation) against AWS-LC fails all six replicas. This is not a new benchmark run; it is a stricter re-evaluation of the published artifact and does not alter the official gate. **This still does not fully verify the original issue:** its acceptance text requires the best measured comparator per operation, while this artifact contains AWS-LC only. The per-operation liboqs/CIRCL comparison coverage must also be restored before claiming final acceptance.

| Operation | Replicas passing 1.00× | Median ratio range | p95 ratio range |
|---|---:|---:|---:|
| `ml-dsa-65 keygen` | 3/6 | 0.895×–1.009× | 0.837×–1.008× |
| `ml-dsa-65 sign` | 6/6 | 0.859×–0.954× | 0.785×–0.915× |
| `ml-dsa-65 verify` | 2/6 | 0.978×–1.075× | 0.976×–1.175× |
| `ml-kem-1024 decaps` | 3/6 | 0.986×–1.069× | 0.927×–1.068× |
| `ml-kem-1024 encaps` | 0/6 | 0.990×–1.092× | 1.003×–1.090× |
| `ml-kem-1024 keygen` | 0/6 | 1.021×–1.120× | 1.014×–1.144× |
| `ml-kem-768 decaps` | 3/6 | 0.991×–1.076× | 0.979×–1.110× |
| `ml-kem-768 encaps` | 0/6 | 0.995×–1.106× | 1.002×–1.142× |
| `ml-kem-768 keygen` | 0/6 | 1.028×–1.118× | 1.027×–1.118× |

## Interpretation

- The current evidence demonstrates that the final `<= 1.00×` acceptance criterion is **not met**; an intermediate `<= 1.5×` pass must not be described as completion of Issue #23.
- The biggest recurring gap in this artifact is ML-KEM key generation (median ratios up to about 1.12× in several replicas), followed by ML-KEM encapsulation/decapsulation and ML-DSA verification. Exact per-replica ratios are retained in the downloaded run artifacts and strict reports.
- Hosted-runner variance is visible. Do not optimize from a rounded ratio or a single run; preserve raw samples and require repeated, matched-host measurements.
- This is a performance-gate audit only. It does not establish current correctness, constant-time security, FIPS validation, or production readiness.

## Verification tooling change

`arena/scripts/evaluate_native_assembly_gate.py` now accepts an optional `--limit RATIO`. The default remains `1.5`, preserving the existing workflow behavior. Passing `--limit 1.0` evaluates the original Issue #23 final target without weakening the intermediate gate. Regression tests cover the default, exact parity, a failing 1.00× case, and invalid thresholds.

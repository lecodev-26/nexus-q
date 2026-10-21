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

## Additional local work (2026-10-21)

The native backend build now enables the upstream-vendored AArch64 NEON arithmetic and Keccak assembly on Linux/Android AArch64, with NEON capability enabled only for that architecture. `portable-only` still disables assembly. This is an architecture-path enablement, not evidence that the original x86-64 1.00× performance target has been met. Local AArch64 differential tests must pass, and the matched x86-64 benchmark plus upstream KAT/ACVP and constant-time workflow gates remain required before acceptance.

### Local AArch64 native-vs-portable diagnostic

The native Arena runner now builds on AArch64 and records nanosecond samples without fabricating x86 TSC values (`cycle_counter_source=unavailable_on_target`, empty `samples_cycles`). Three alternating local rounds were run on Android/AArch64 with 100 warmups and 1,000 samples per operation per round. The raw JSONL is retained outside the repository at `$HOME/nexusq-issue23-baseline/local-aarch64/`. This compares the upstream AArch64 assembly path with the same vendored implementation's portable-C path, not with AWS-LC and not with the x86-64 final gate.

| Operation | Native assembly median (µs) | Portable C median (µs) | Median ratio | Native assembly p95 (µs) | Portable C p95 (µs) | p95 ratio |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-65 keygen | 92.62 | 191.69 | 0.483× | 96.00 | 213.62 | 0.449× |
| ML-DSA-65 sign | 223.19 | 619.65 | 0.360× | 603.38 | 1917.15 | 0.315× |
| ML-DSA-65 verify | 88.31 | 179.77 | 0.491× | 90.39 | 192.54 | 0.469× |
| ML-KEM-1024 decaps | 45.85 | 79.46 | 0.577× | 47.38 | 82.15 | 0.577× |
| ML-KEM-1024 encaps | 37.23 | 69.85 | 0.533× | 38.23 | 71.15 | 0.537× |
| ML-KEM-1024 keygen | 36.62 | 73.15 | 0.501× | 38.08 | 76.31 | 0.499× |
| ML-KEM-768 decaps | 31.31 | 51.69 | 0.606× | 32.62 | 52.92 | 0.616× |
| ML-KEM-768 encaps | 25.54 | 44.62 | 0.572× | 27.31 | 59.38 | 0.460× |
| ML-KEM-768 keygen | 25.46 | 46.38 | 0.549× | 29.85 | 48.92 | 0.610× |

The AArch64 assembly path was faster than portable C in all nine operation medians in this local diagnostic. ML-DSA signing's p95 remains noisy, so this is directional evidence rather than a release claim. It does not resolve the separate x86-64 comparison against AWS-LC, nor restore liboqs/CIRCL as the best-per-operation comparators required by the original issue.

### Termux hybrid API follow-up (21 October 2026)

The first 20-iteration Phase 17 benchmark showed a misleading ML-KEM-1024 hybrid encapsulation mean of roughly 3.76 ms with `native-backend`. This was investigated using two 100-call per-operation sample rounds after 10 warmups for both ordinary and prepared-public-key APIs. On this Android/AArch64 device:

| Configuration | API | Run 1 median / P95 | Run 2 median / P95 |
|---|---|---:|---:|
| Default RustCrypto | serialized public key | 498.7 / 533.8 µs | 1,085.5 / 3,773.2 µs |
| Default RustCrypto | prepared public key | 479.0 / 507.3 µs | 476.9 / 509.2 µs |
| Native backend | serialized public key | 116.2 / 149.2 µs | 116.0 / 138.1 µs |
| Native backend | prepared public key | 115.7 / 316.0 µs | 115.7 / 130.8 µs |

The high aggregate means did not reproduce in the native per-call median/P95 data; the default serialized-key path did show a high-variance second run. The cause of these outliers is not established; OS entropy or scheduler/backend latency are possibilities, not confirmed diagnoses. The local benchmark now reports per-call median and P95 for these APIs to avoid relying on a short aggregate mean. The native path was consistently faster at the median in these local runs, though the default path's tail variability needs further investigation before making a production-performance claim. These Android measurements are not substitutes for the issue's matched x86-64 AWS-LC/liboqs/CIRCL gate.

### Matched-CSPRNG kernel-gate experiment (Android/AArch64)

The standalone native runner previously called the OS `getrandom` syscall for every randomized kernel operation, while the AWS-LC C reference runner uses AWS-LC's `RAND_bytes` DRBG. To avoid charging different RNG implementations to the kernel comparison, the native backend now has an opt-in `aws-lc-rng` feature for the Arena runner only. The default library remains on `getrandom`; the native-backend gate builds its benchmark runner with `aws-lc-rng`, and the separate core-production gate continues to measure the real production RNG path. Every benchmark record emits `environment.rng_source` so the RNG mode is explicit.

Three alternating local AArch64 rounds with 100 warmups and 1,000 samples per operation, using `aws-lc-rand-bytes` for both the native-assembly and portable-C variants, produced the following pooled sample statistics. Raw JSONL is stored outside the repository at `$HOME/nexusq-issue23-baseline/local-aarch64-common-rng/`.

| Operation | Native median (µs) | Portable median (µs) | Median ratio | Native p95 (µs) | Portable p95 (µs) | p95 ratio |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-65 keygen | 93.46 | 192.54 | 0.485× | 99.39 | 212.23 | 0.468× |
| ML-DSA-65 sign | 215.73 | 586.88 | 0.368× | 599.69 | 1783.38 | 0.336× |
| ML-DSA-65 verify | 88.31 | 179.46 | 0.492× | 89.92 | 193.00 | 0.466× |
| ML-KEM-1024 decaps | 45.85 | 76.92 | 0.596× | 47.08 | 95.77 | 0.492× |
| ML-KEM-1024 encaps | 36.92 | 66.54 | 0.555× | 38.15 | 68.85 | 0.554× |
| ML-KEM-1024 keygen | 35.62 | 71.31 | 0.499× | 36.92 | 76.61 | 0.482× |
| ML-KEM-768 decaps | 31.31 | 51.62 | 0.607× | 71.39 | 53.23 | 1.341× |
| ML-KEM-768 encaps | 25.23 | 44.23 | 0.570× | 25.77 | 45.46 | 0.567× |
| ML-KEM-768 keygen | 24.39 | 46.15 | 0.528× | 25.85 | 101.31 | 0.255× |

The native assembly path remains faster in all nine medians under the matched RNG. Tail outliers persist on this mobile host (notably ML-KEM-768 decapsulation and portable key generation), so these local results remain directional, not a substitute for repeated x86-64 gate runs.

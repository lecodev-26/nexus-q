# Experimental native backend (Rust API + C + assembly)

Status: **experimental, isolated, not wired into `nexusq-core`.** This document records the design, the decisions and the evidence. A decision is only marked verified when reproducible evidence is linked.

Tracking: [Issue #48](https://github.com/lecodev-26/nexus-q/issues/48). Branch: `perf/native-backend-hybrid`. Workflow: `.github/workflows/native-backend-gate.yml`.

## Architecture

```
crates/nexusq-native-backend   Rust API (safe, fixed-size key types, ZeroizeOnDrop secrets)
  ├─ csrc/                      NEXUS-Q configuration of the vendored C libraries
  │    nq_mlkem_config.h        namespace nq_mlkem*, static internals, custom RNG + CPU dispatch
  │    nq_mldsa_config.h        namespace nq_mldsa65, same policy
  │    nq_fips202_x86_64_*.h    FIPS202 backend: upstream AVX2 x4 + s2n-bignum scalar x1
  │    nq_*_all.c / *_asm.S     single-compilation-unit builds plus ABI guards
  ├─ tests/differential.rs      byte-exact differential tests against vendor/ml-kem, vendor/ml-dsa
  └─ ct/run.sh                  valgrind constant-time harness with negative and coverage controls
vendor/mlkem-native             mlkem-native v2.0.0 d1b2fe78 (unmodified, same commit as AWS-LC ec05f25e)
vendor/mldsa-native             mldsa-native v2.0.0 834a90d5 (unmodified, same commit as AWS-LC ec05f25e)
vendor/s2n-bignum               sha3_keccak_f1600.S at 4b5f8214 (unmodified, same commit as AWS-LC ec05f25e)
arena/runners/nexusq-native     Arena runner: same JSON schema and statistics as arena/runners/nexusq
```

- Rust owns the API, input validation (lengths, ML-DSA context ≤ 255 bytes), error mapping, zeroization and the RNG (`getrandom`, the OS CSPRNG).
- C and assembly own the arithmetic.
- On x86-64 Linux the AVX2 assembly is compiled from `.S` files only (no `-mavx2` for C). It is selected at runtime with `__builtin_cpu_supports("avx2") && ("bmi2")`, the AWS-LC policy. Otherwise the portable C path of the same library runs (`portable-only` forces it). AArch64 currently uses the portable C path; its NEON backend is not enabled yet.
- The crates are standalone (`[workspace]` in their manifests), like `arena/runners/nexusq`. The root workspace, its `Cargo.lock` and every production crate are unchanged.

## Decisions and evidence

| # | Decision | Reason | Evidence |
|---|---|---|---|
| D1 | Use mlkem-native/mldsa-native instead of hand-writing new kernels | They are the exact arithmetic cores of the comparator, with HOL-Light/CBMC proofs upstream. The previous in-house AVX2 kernels were slower than RustCrypto scalar code. | Previous audit; `vendor-integrity` job |
| D2 | Pin the commits imported by AWS-LC `ec05f25e` | Equal code, so any remaining difference comes from integration and not from the algorithms | `vendor-integrity`: `diff -r` vs upstream and `grep` in AWS-LC `META.yml` |
| D3 | Replace upstream's portable C 1-way Keccak with s2n-bignum `sha3_keccak_f1600` | AWS-LC routes every x86-64 1-way Keccak call to this routine (`crypto/fipsmodule/sha/keccak1600.c`). It was the only algorithmic difference left and is about 18 % of executed instructions. | A/B on the same host, 10 interleaved rounds: −2 % to −4 % on all nine operations, −3.8 % on ML-KEM-768 decaps. Byte-exact differential tests pass with both Keccak variants. |
| D4 | Hidden, renamed assembly symbols (`nq_*`, `S2N_BN_HIDE_SYMBOLS`) and `static` internals | No clash when linked together with AWS-LC or aws-lc-rs | `readelf`: `nq_sha3_keccak_f1600` is `GLOBAL HIDDEN` |
| D5 | Build-time ABI guards | Rust FFI declarations must match the C prototypes exactly. A mismatch is now a compile error instead of memory corruption. | `csrc/nq_*_all.c`, `-Werror=incompatible-pointer-types` |
| D6 | Benchmark contract `fips_operation_v1` from encoded keys | encaps and verify start from public-key bytes (FIPS 203 modulus check and `H(ek)`, FIPS 204 expansion of A and t1 on every call). decaps and sign start from secret-key bytes. This matches the AWS-LC adapter and removes the cached-verifier asymmetry of the current gate. | `arena/runners/nexusq-native/src/main.rs` |
| D7 | ML-DSA sign uses one key per round, hedged signing, empty context (AWS-LC adapter protocol) | Same work as the comparator. **This differs from `arena/runners/nexusq` (64 seeds × 16, deterministic) and needs reviewer sign-off.** | runner source |
| D8 | Official verdict = unmodified `evaluate_native_assembly_gate.py`, 3 rounds, 1.5x on both median and p95 | The threshold and the protocol are not relaxed. Nine additional rounds, bootstrap CIs and steal-time capture are informational only; they show how robust the verdict is. | workflow `benchmark-gate` (6 independent replicas) |
| D9 | **Rejected:** s2n-bignum `sha3_keccak4_f1600_alt` for the 4-way permutation (the routine AWS-LC uses) | The perf profile on EPYC 7763 suggested it, but the measurements did not support it. In-process A/B: about 1 % slower on Zen 3, neutral on Zen 4/5. Upstream's x4 routine is kept. | commit `9e56d1b`, reverted in `ff8ac01`; runs [38798035934](https://github.com/lecodev-26/nexus-q/actions/runs/38798035934), [38798036136](https://github.com/lecodev-26/nexus-q/actions/runs/38798036136) |
| D10 | A/A control of the gate protocol (`native-backend-aa-control.yml`) | It measures how often hosted-runner noise alone breaks the p95 limit. Evaluator, threshold and protocol are unchanged. | see "Gate reliability" below |

## Security evidence (blocking)

1. **Differential tests** against the RustCrypto code NEXUS-Q ships (10 000 iterations per algorithm in CI, plus 2000 with `portable-only` and 2000 with `upstream-c-keccak`, on x86-64 and AArch64).
   - ML-KEM: pk, sk, ct and ss are byte-identical. Implicit rejection agrees with RustCrypto and never returns the honest secret. Cross-decapsulation is tested. A FIPS 203 ek with a coefficient ≥ q is rejected, and a dk with a corrupted `H(ek)` is rejected.
   - ML-DSA-65: keys and deterministic signatures are byte-identical for random messages of 0–511 bytes and contexts of 0–255 bytes. Hedged signatures verify under RustCrypto. Tampered signature, message or context gives the same rejection verdict in both implementations. A context longer than 255 bytes is rejected.
2. **Upstream suites at the pinned commits** (`make run_func run_kat run_acvp`), including the NIST ACVP vectors.
3. **Constant time** (`ct/run.sh`): valgrind memcheck runs with all RNG output and all secret keys marked undefined, using the libraries' CT-testing declassification hooks. It covers keygen, encaps, decaps (including the implicit-rejection path), sign and verify, and must report 0 errors.
   - Negative control: a secret-dependent branch must be detected.
   - Coverage control: callgrind must show that the AVX2 and s2n-bignum assembly executed.
   - Limitation: this does not detect variable-latency instructions. Upstream formal proofs cover functional correctness of the assembly, not timing.
4. **Unsafe policy**: every `unsafe` site carries a `// SAFETY:` justification (`.github/scripts/check-native-backend-unsafe.py`).
5. **Supply chain**: `cargo audit` runs on both new lockfiles. The vendored trees are verified byte-for-byte against upstream.

## Licensing note

mlkem-native and mldsa-native are Apache-2.0 OR ISC OR MIT. The s2n-bignum repository is Apache-2.0 OR ISC OR MIT-0, but `sha3_keccak_f1600.S` carries `SPDX-License-Identifier: Apache-2.0` because it derives from OpenSSL. Binaries that include this backend therefore contain Apache-2.0-only code and must ship `vendor/s2n-bignum/LICENSE` and `NOTICE`. The `upstream-c-keccak` feature removes that file from the build.

## Measurements on GitHub-hosted runners

All numbers are NEXUS-Q / AWS-LC ratios from the **unmodified official evaluator**, three alternating rounds, 1000 samples per round. They are extracted from the job logs. Local measurements (Intel Xeon KVM VM, 2 vCPU) are not used as gate evidence.

### Official verdict per replica

| Run | Commit | Replica | CPU | Verdict | Failing ops (median / p95) |
|---|---|---|---|---|---|
| [38795522829](https://github.com/lecodev-26/nexus-q/actions/runs/38795522829) | b84726d | 1 | AMD EPYC 7763 | PASS | - |
| [38795522829](https://github.com/lecodev-26/nexus-q/actions/runs/38795522829) | b84726d | 3 | AMD EPYC 9V74 | PASS | - |
| [38795522829](https://github.com/lecodev-26/nexus-q/actions/runs/38795522829) | b84726d | 4 | AMD EPYC 7763 | PASS | - |
| [38795522829](https://github.com/lecodev-26/nexus-q/actions/runs/38795522829) | b84726d | 2 | AMD EPYC 7763 | PASS | - |
| [38796903676](https://github.com/lecodev-26/nexus-q/actions/runs/38796903676) | 9054d10 | 5 | AMD EPYC 9V45 | PASS | - |
| [38796903676](https://github.com/lecodev-26/nexus-q/actions/runs/38796903676) | 9054d10 | 2 | AMD EPYC 7763 | PASS | - |
| [38796903676](https://github.com/lecodev-26/nexus-q/actions/runs/38796903676) | 9054d10 | 6 | AMD EPYC 9V74 | PASS | - |
| [38796903676](https://github.com/lecodev-26/nexus-q/actions/runs/38796903676) | 9054d10 | 1 | AMD EPYC 7763 | PASS | - |
| [38796903676](https://github.com/lecodev-26/nexus-q/actions/runs/38796903676) | 9054d10 | 3 | AMD EPYC 7763 | PASS | - |
| [38796903676](https://github.com/lecodev-26/nexus-q/actions/runs/38796903676) | 9054d10 | 4 | AMD EPYC 7763 | FAIL | ml-kem-1024 decaps 1.102 / 1.639; ml-kem-1024 encaps 1.145 / 1.596 |
| [38798036136](https://github.com/lecodev-26/nexus-q/actions/runs/38798036136) | 9e56d1b (s2n x4, reverted) | 2 | AMD EPYC 7763 | PASS | - |
| [38798036136](https://github.com/lecodev-26/nexus-q/actions/runs/38798036136) | 9e56d1b (s2n x4, reverted) | 1 | AMD EPYC 7763 | PASS | - |
| [38798036136](https://github.com/lecodev-26/nexus-q/actions/runs/38798036136) | 9e56d1b (s2n x4, reverted) | 6 | AMD EPYC 7763 | PASS | - |
| [38798036136](https://github.com/lecodev-26/nexus-q/actions/runs/38798036136) | 9e56d1b (s2n x4, reverted) | 5 | AMD EPYC 9V74 | PASS | - |
| [38798036136](https://github.com/lecodev-26/nexus-q/actions/runs/38798036136) | 9e56d1b (s2n x4, reverted) | 4 | INTEL(R) XEON(R) PLATINUM 8573C | PASS | - |
| [38798036136](https://github.com/lecodev-26/nexus-q/actions/runs/38798036136) | 9e56d1b (s2n x4, reverted) | 3 | AMD EPYC 7763 | FAIL | ml-kem-768 decaps 1.086 / 1.516 |
| [38798844655](https://github.com/lecodev-26/nexus-q/actions/runs/38798844655) | cd42080 | 2 | AMD EPYC 7763 | PASS | - |
| [38798844655](https://github.com/lecodev-26/nexus-q/actions/runs/38798844655) | cd42080 | 6 | AMD EPYC 7763 | PASS | - |
| [38798844655](https://github.com/lecodev-26/nexus-q/actions/runs/38798844655) | cd42080 | 3 | AMD EPYC 9V74 | PASS | - |
| [38798844655](https://github.com/lecodev-26/nexus-q/actions/runs/38798844655) | cd42080 | 5 | AMD EPYC 9V74 | PASS | - |
| [38798844655](https://github.com/lecodev-26/nexus-q/actions/runs/38798844655) | cd42080 | 4 | AMD EPYC 7763 | PASS | - |
| [38798844655](https://github.com/lecodev-26/nexus-q/actions/runs/38798844655) | cd42080 | 1 | AMD EPYC 7763 | FAIL | ml-kem-1024 encaps 1.109 / 1.594 |
| [38799671219](https://github.com/lecodev-26/nexus-q/actions/runs/38799671219) | 1433771 | 4 | AMD EPYC 7763 | PASS | - |
| [38799671219](https://github.com/lecodev-26/nexus-q/actions/runs/38799671219) | 1433771 | 3 | AMD EPYC 9V74 | PASS | - |
| [38799671219](https://github.com/lecodev-26/nexus-q/actions/runs/38799671219) | 1433771 | 1 | AMD EPYC 9V45 | PASS | - |
| [38799671219](https://github.com/lecodev-26/nexus-q/actions/runs/38799671219) | 1433771 | 6 | AMD EPYC 7763 | PASS | - |
| [38799671219](https://github.com/lecodev-26/nexus-q/actions/runs/38799671219) | 1433771 | 5 | AMD EPYC 7763 | PASS | - |
| [38799671219](https://github.com/lecodev-26/nexus-q/actions/runs/38799671219) | 1433771 | 2 | AMD EPYC 9V74 | PASS | - |
| [38800297448](https://github.com/lecodev-26/nexus-q/actions/runs/38800297448) | 8fd2657 (PR #50) | 5 | AMD EPYC 9V74 | PASS | - |
| [38800297448](https://github.com/lecodev-26/nexus-q/actions/runs/38800297448) | 8fd2657 (PR #50) | 2 | AMD EPYC 7763 | PASS | - |
| [38800297448](https://github.com/lecodev-26/nexus-q/actions/runs/38800297448) | 8fd2657 (PR #50) | 3 | AMD EPYC 9V74 | PASS | - |
| [38800297448](https://github.com/lecodev-26/nexus-q/actions/runs/38800297448) | 8fd2657 (PR #50) | 4 | AMD EPYC 9V45 | PASS | - |
| [38800297448](https://github.com/lecodev-26/nexus-q/actions/runs/38800297448) | 8fd2657 (PR #50) | 6 | AMD EPYC 7763 | FAIL | ml-kem-1024 keygen 1.129 / 1.553; ml-kem-768 decaps 1.082 / 1.578 |
| [38800297448](https://github.com/lecodev-26/nexus-q/actions/runs/38800297448) | 8fd2657 (PR #50) | 1 | AMD EPYC 9V74 | PASS | - |

**Status: not green.** 30 of 34 replicas pass and 4 fail. Every failure is a p95 tail on ML-KEM on AMD EPYC 7763, with medians of 1.08–1.15. A single slow episode inflates one round. For example, in run 38796903676 replica 4, ML-KEM-1024 decaps p95 is 37.5 µs against a 24.6 µs median, and the extended statistics show it in one round of 12. Run 38799671219 passed 6/6 on the branch head, but the PR run 38800297448 on the same code failed one replica (ML-KEM-768 decaps, 1.082 / 1.578).

Tails are symmetric between the two implementations. Over the 204 ML-KEM (operation, replica) observations per implementation, NEXUS-Q shows p95/median > 1.25 in 10 cases and AWS-LC in 9 cases. AWS-LC tails do not trip the one-sided gate; they push the ratio below 1 (for example 0.724 for ML-KEM-768 encaps in run 38796903676 replica 3). No NEXUS-Q-specific tail mechanism is visible in the data.

### Ranges per CPU (official 3-round windows, excluding the reverted commit)
EPYC 7763 (Zen 3): 16 replicas (excluding the reverted commit)

| Operation | median ratio min-max | p95 ratio min / median / max | replicas with p95 > 1.5 |
|---|---|---|---|
| ml-kem-768 keygen | 1.127-1.138 | 0.993 / 1.135 / 1.163 | 0/16 |
| ml-kem-768 encaps | 1.113-1.123 | 0.724 / 1.115 / 1.239 | 0/16 |
| ml-kem-768 decaps | 1.077-1.134 | 0.837 / 1.078 / 1.578 | 1/16 |
| ml-kem-1024 keygen | 1.126-1.224 | 0.773 / 1.133 / 1.553 | 1/16 |
| ml-kem-1024 encaps | 1.103-1.207 | 0.717 / 1.111 / 1.596 | 2/16 |
| ml-kem-1024 decaps | 1.066-1.154 | 0.763 / 1.080 / 1.639 | 1/16 |
| ml-dsa-65 keygen | 0.999-1.007 | 0.935 / 1.005 / 1.208 | 0/16 |
| ml-dsa-65 sign | 0.894-0.970 | 0.829 / 0.875 / 0.936 | 0/16 |
| ml-dsa-65 verify | 1.072-1.080 | 1.041 / 1.191 / 1.210 | 0/16 |

EPYC 9V74/9V45 (Zen 4/5): 12 replicas (excluding the reverted commit)

| Operation | median ratio min-max | p95 ratio min / median / max | replicas with p95 > 1.5 |
|---|---|---|---|
| ml-kem-768 keygen | 1.019-1.107 | 0.924 / 1.047 / 1.102 | 0/12 |
| ml-kem-768 encaps | 1.016-1.088 | 0.770 / 1.027 / 1.114 | 0/12 |
| ml-kem-768 decaps | 0.997-1.046 | 0.994 / 1.021 / 1.066 | 0/12 |
| ml-kem-1024 keygen | 1.024-1.065 | 0.940 / 1.034 / 1.060 | 0/12 |
| ml-kem-1024 encaps | 0.978-1.067 | 0.916 / 1.012 / 1.067 | 0/12 |
| ml-kem-1024 decaps | 0.975-1.040 | 0.959 / 0.994 / 1.277 | 0/12 |
| ml-dsa-65 keygen | 0.891-0.930 | 0.768 / 0.893 / 1.036 | 0/12 |
| ml-dsa-65 sign | 0.808-0.934 | 0.790 / 0.864 / 0.935 | 0/12 |
| ml-dsa-65 verify | 0.974-1.006 | 0.697 / 0.973 / 1.136 | 0/12 |


ML-KEM-768 decaps, which the review singled out: on Zen 3 its median ratio is 1.077–1.134. Its p95 stays at or below 1.14 except for two single-round tails, 1.516 (run 38798036136, reverted commit) and 1.578 (run 38800297448).

### Gate reliability: A/A control

AWS-LC is benchmarked against itself with the exact gate protocol and judged by the unmodified evaluator:

| Run | Official windows (rounds 1-3) failing | All 3-round windows failing | Worst false p95 ratio |
|---|---|---|---|
| [38798130380](https://github.com/lecodev-26/nexus-q/actions/runs/38798130380) | 2 / 10 | 4 / 40 | 2.350 (Xeon 8370C, ML-KEM-768 keygen) |
| [38798857918](https://github.com/lecodev-26/nexus-q/actions/runs/38798857918) | 0 / 10 | 2 / 40 | 1.585 (EPYC 9V74, ML-DSA-65 keygen) |
| **Total** | **2 / 20 (10 %)** | **6 / 80 (7.5 %)** | |

Identical code therefore fails the 1.5x p95 limit in about 7.5–10 % of evaluations on hosted runners. The NEXUS-Q failure rate (4 of 34, 12 %) is of the same order. The NEXUS-Q rate is somewhat higher because on Zen 3 its medians start 8–14 % above AWS-LC, which leaves less headroom. This does **not** make the failing runs green. It means hosted runners cannot give a deterministic p95 verdict, for NEXUS-Q or for AWS-LC itself. Options for the maintainers (not applied here, because they change the protocol): pin both runners to the same core, use a dedicated or self-hosted runner, or require the limit on every one of N independent replicas.

### Zen 3 median gap (systematic, not a gate failure)

The in-process A/B diagnostic (`diag/inproc_ab.c`, `native-backend-diag.yml`) links both libraries into one process and alternates calls per iteration. On EPYC 7763 the NEXUS-Q build is still 7–11 % slower on ML-KEM, also with deterministic RNG inputs. So the cause is neither the RNG nor the harness nor cross-process noise. On Zen 4/5 the difference is within ±3 %. On the local Intel KVM, NEXUS-Q is 5–10 % faster.

- Measured: AWS-LC's compiler flags (`-std=gnu11 -DNDEBUG -fvisibility=hidden -fno-common`) recover 1–3 points (runs 38796903942, 38798035934). The s2n x4 permutation recovers nothing (D9).
- Hypothesis, not verified: the remaining difference lies in the FIPS202 sponge layer. AWS-LC replaces mlkem-native's (`MLK_CONFIG_FIPS202_CUSTOM_HEADER` with its own absorb/squeeze and 64-bit lane XOR). In the profiles, mlkem-native's `keccakf1600_extract_bytes`/`xor_bytes` account for 3.7–5.3 % of ML-KEM time on Zen 3, while AWS-LC's equivalent is under 1 %. Testing this requires a custom FIPS202 layer, which is new constant-time-relevant code that needs its own review.

## Not done yet (explicitly)

- The backend is not wired into `nexusq-core`, CLI, server or SDK. The production cryptographic path is unchanged.
- AArch64 NEON backend: not enabled. AArch64 is functionally tested only on the portable C path.
- No FIPS 140-3 validation. No pairwise consistency test (PCT) is run, which matches the non-FIPS AWS-LC build used as the comparator.
- The gate is not green (see above). The p95 failures match the A/A false-failure rate, but they are not declared green.
- The Zen 3 median gap (7–14 % on ML-KEM) is not closed; see the hypothesis above.
- No independent external review of this integration. Phase 21 (external audit) remains open, so this work does not make NEXUS-Q v1.0 or v2 production-ready.

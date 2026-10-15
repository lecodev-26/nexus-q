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
| D8 | Official verdict = unmodified `evaluate_native_assembly_gate.py`, 3 rounds, 1.5x on both median and p95 | The threshold and the protocol are not relaxed. Nine additional rounds, bootstrap CIs and steal-time capture are informational only; they show how robust the verdict is. | workflow `benchmark-gate` (4 independent replicas) |

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

## Measurements

CI results for each commit are recorded in the PR (job summaries and artifacts `native-backend-gate-<sha>-replica-<n>`). Local measurements (Intel Xeon KVM VM, 2 vCPU) are not a substitute for the GitHub-hosted runners and are not used as gate evidence.

## Not done yet (explicitly)

- The backend is not wired into `nexusq-core`, CLI, server or SDK. The production cryptographic path is unchanged.
- AArch64 NEON backend: not enabled. AArch64 is functionally tested only on the portable C path.
- No FIPS 140-3 validation. No pairwise consistency test (PCT) is run, which matches the non-FIPS AWS-LC build used as the comparator.
- No independent external review of this integration. Phase 21 (external audit) remains open, so this work does not make NEXUS-Q v1.0 or v2 production-ready.

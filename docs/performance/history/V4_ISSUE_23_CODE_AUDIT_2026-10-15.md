# NEXUS-Q V4 Issue #23 — focused code audit (2026-10-15)

**Reviewed head:** `d7fcc3fc77eb1288c9e508676e42e4c5f3128f40` (`d7fcc3f`)
**PR:** [#46](https://github.com/lecodev-26/nexus-q/pull/46)
**CI evidence:** [run 38648027975](https://github.com/lecodev-26/nexus-q/actions/runs/38648027975)
**Status:** NOT ACCEPTED; no push/commit performed for this audit update.

## Executive verdict

Do not publish this branch as a release candidate or claim parity with AWS-LC. The current CI run is red for two Clippy errors and the existing per-operation 1.5x performance gate. The kernel work is an experimental integration, not yet an accepted production crypto backend.

## Evidence-backed status

| Area | Status | Evidence / reason |
|---|---|---|
| Rust workspace `cargo check --locked` | Pass in this run | CI log shows check completed before Clippy |
| Formatting / static diff checks | Pass locally | `cargo fmt --all -- --check`, targeted `rustfmt --check`, `git diff --check` |
| Kernel unsafe policy | Pass in this run | CI `check-kernel-unsafe.py` passed; `nexusq-core` remains safe-only |
| Secret scan | Pass in this run | CI secret scanning job |
| Dependency provenance | Pass in this run | V4 Phase 0 provenance job |
| Security/audit/SBOM input job | Pass in this run | CI security job reported pass; this is not an external cryptographic audit |
| Clippy | **Fail** | `api.rs` `ShakeX4::absorb` has two `needless_range_loop` diagnostics under `-D warnings` |
| Arena schema and coverage | Pass | 10 NEXUS-Q records, 9 AWS-LC records, all nine conventional operations; cached verify is separate |
| Performance gate | **Fail** | Eight operations exceed 1.5x median; p95 also fails for those and ML-DSA verify |
| SHAKE x4 end-to-end benefit | Not established | No accepted before/after matched-run attribution; all ML-KEM medians remain above 3.5x |
| ML-KEM NTT/INTT/basemul SIMD | Not implemented | Vendored production arithmetic remains scalar `module-lattice` |
| ML-DSA kernel integration | Not implemented | `ml-dsa 0.1.1` remains external; no optimized backend integration |
| aarch64 NEON/SHA3 | Not implemented | No production path in scope found |
| ACVP/FIPS end-to-end KAT and full security gates | Open | Current run does not provide that evidence; fuzz soaks were skipped |
| Release readiness | **Blocked** | CI red, performance gate red, security/release acceptance incomplete |

## Exact performance failures from CI run 38648027975

Ratios are NEXUS-Q/AWS-LC medians from the same Arena run; threshold remains 1.500x and was not changed.

| Operation | Median ratio |
|---|---:|
| ML-DSA-65 keygen | 5.798x |
| ML-DSA-65 sign | 4.991x |
| ML-KEM-1024 keygen | 4.715x |
| ML-KEM-1024 encaps | 4.065x |
| ML-KEM-1024 decaps | 3.817x |
| ML-KEM-768 keygen | 4.267x |
| ML-KEM-768 encaps | 3.670x |
| ML-KEM-768 decaps | 3.523x |

P95 additionally fails for the eight operations above and ML-DSA-65 verify (1.632x). Do not compare these numbers to prior runs as a causal SHAKE x4 speedup without a same-host controlled before/after run and comparable commit/configuration.

## Source-level findings

1. `crates/nexusq-kernels/src/api.rs`: `ShakeX4::absorb` has Clippy-only loop-style issues. A local, behavior-preserving iterator rewrite is prepared but not yet CI-validated.
2. `crates/nexusq-kernels/src/x86_64/avx2.rs`: x4 Keccak AVX2 path exists; its existence alone does not mean all SHAKE or PQC calls use it. The API comments explicitly say single-state dispatch remains scalar.
3. `vendor/ml-kem/src/algebra.rs`: batched `matrix_sample_ntt` is conditionally wired to `ShakeX4`; NTT, inverse NTT and basemul remain scalar. The sampler's rejection loop is variable-time based on public XOF-derived samples, consistent with the documented allowed category, but bit-exactness still depends on CI differential/KAT evidence.
4. `vendor/ml-kem/src/param.rs`: generic dimension bounds were propagated for `K*K`; workspace check passed in the reviewed run.
5. `vendor/ml-kem/src/compress.rs`: CI emits future-compatibility warnings for `u16::truncate`; they were warnings, not the Clippy blockers in this run. Prefer fully qualified trait syntax in a separate behavior-preserving cleanup if required by the toolchain policy.
6. ML-DSA remains `ml-dsa 0.1.1`; no vendorized source, NTT SIMD, sampler/packing optimization, or signing-path integration is evidenced.
7. The measurement pipeline is materially better instrumented (same-run AWS-LC comparator, raw samples, median/p95, operation coverage and fail-closed 1.5x gate), but its current outcome is a real failure. Evidence archiving correctly skipped because not every gate passed.
8. `cargo audit`/`cargo deny` job status passed in this run as reported by the workflow, but that is dependency-policy evidence only—not validation of constant-time behavior or cryptographic design. The long fuzz soak jobs were skipped for this V4 run.

## Phase checklist disposition

- **F0 measurement plumbing:** harness/metadata/schema/coverage are present and evidenced; acceptance remains **OPEN** until the PR CI is green and the measurement contract has been reviewed end to end. The performance gate itself is implemented but fails.
- **F1 SHAKE x4 effect:** **OPEN**; no defensible causal before/after result.
- **F2 ML-KEM SIMD:** **OPEN**; SHAKE x4 matrix sampling is an experimental partial integration, while NTT/INTT and basemul SIMD are absent.
- **F3 ML-DSA SIMD/vendorization:** **OPEN**.
- **F4 aarch64:** **OPEN**.
- **F5 profiling/assembly:** **OPEN**; no profile evidence justifies handwritten assembly.
- **F6 security gates:** **OPEN**; KAT/ACVP, timing analysis, long fuzz, sanitizer/Miri and external review evidence is incomplete.
- **F7 release:** **OPEN**; not release-ready.

## Local working-tree change

A lint-only rewrite in `crates/nexusq-kernels/src/api.rs` iterates over the first input slice and enumerates lane inputs instead of indexing arrays by range variables. The local formatting checks pass. No local builds, tests, benchmarks, commits, pushes, PR merges, or issue closures were performed. This change is not considered fixed until a subsequent CI run validates it.

## Next step

After authorization to push, send only the `api.rs` lint fix and the audit/tracker evidence update as one small change, wait for the single PR CI, then re-audit. Do not start NTT SIMD until F0 is green and the SHAKE x4 before/after evidence can be interpreted.

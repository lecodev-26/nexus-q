# NEXUS-Q V4 — Issue #23 execution tracker

**Source of truth:** [Issue #23](https://github.com/lecodev-26/nexus-q/issues/23)  
**Working PR:** [#46](https://github.com/lecodev-26/nexus-q/pull/46), branch `v4/issue-23-kernel-work`, targeting `nexusqv4`

**Baseline:** reviewed V3 snapshot on `nexusqv4`

**Status (source audit 2026-10-12):** the Phase 0 measurement harness, shared operation-contract metadata, and per-operation median/p95 gate are present in the branch. The configured milestone is 1.5x, with fail-closed handling for missing operations, contract mismatch, malformed provenance, and ratio regressions. Phase 0 acceptance remains unchecked until the exact PR-head CI artifacts and comparison report have been reviewed; this tracker does not assert the outcome of the latest CI run. The scalar kernel crate is now present with Keccak-f[1600]/SHAKE128/SHAKE256 and ML-KEM reference operations including NTT/inverse NTT, basemul, reduction/normalization, compression/decompression, packing/unpacking, CBD, and rejection sampling. This is scalar reference groundwork only: independent end-to-end KAT/differential evidence, optimized SIMD/assembly kernels, complete security evidence, and phase acceptance remain open.

This checklist mirrors the phases and acceptance criteria in Issue #23. Keep it updated in the working PR with links to commits, CI runs, benchmark artifacts, test evidence, and security review. Do not check an item merely because code exists; check it only after the evidence has been reviewed. Issue #23 remains open until its complete definition of done is met.

## Phase 0 — Trustworthy measurement (blocking)

- [x] Make `arena/runners/nexusq` resolve the exact local kernel/backend source under development; prove it with `cargo tree -i ml-kem` (or the corresponding resolved dependency tree). _Evidence: `[patch.crates-io]` in `arena/runners/nexusq/Cargo.toml`; Phase 0 CI enforces vendor resolution (run 38123650717)._
- [x] Commit required vendored sources and patch configuration, or remove them; no untracked vendor/patch dependency. _Evidence: `vendor/ml-kem` and `vendor/module-lattice` are tracked together with the patch configuration._
- [ ] Benchmark all nine operations through the same primitive layer: ML-KEM-768/1024 keygen, encaps, decaps; ML-DSA-65 keygen, sign, verify. See [V4 Arena baseline audit](V4_ARENA_BASELINE_AUDIT.md) for the archived-result limitations.
- [ ] Use at least 1,000 measured iterations and 100 warmups; `black_box` inputs and outputs; report median, p95, and standard deviation.
- [ ] Record CPU model/features, governor, toolchain, build/profile and environment metadata in JSONL; compare implementations in the same CI job.
- [ ] Add cycle counts (`rdtsc`/`cntvct`) alongside wall-clock timing where supported, with a safe unsupported-platform fallback.
- [ ] Add a per-operation CI gate against the best comparator from the same run and the current milestone ratio: 1.5x → 1.2x → 1.05x → 1.00x.

## Phase 1 — Kernel crate skeleton

> Source state reviewed 2026-10-12: `crates/nexusq-kernels` contains safe scalar Keccak-f[1600]/SHAKE128/SHAKE256 and ML-KEM reference operations for NTT/inverse NTT, basemul, reduce/freeze, compression/decompression, pack/unpack, CBD, and rejection sampling. Earlier CI evidence is historical and tied to the SHA named in its linked run; it must not be treated as validation of the current PR head. These routines are reference groundwork, not independent end-to-end FIPS 203 KAT or optimized-kernel differential evidence. Only the scalar backend is selectable; optimized kernels and full security/acceptance evidence remain incomplete.

- [x] Add `crates/nexusq-kernels`; it is the only crate permitted to contain `unsafe` code. _Evidence: crate present in the workspace; fmt and clippy (-D warnings) clean at this commit._
- [ ] Complete and accept the portable scalar reference-kernel phase: the source contains Keccak-f[1600]/SHAKE128/SHAKE256; NTT/inverse NTT; basemul; reduce/freeze; compression/decompression; packing/unpacking; CBD; and rejection-sampling routines. Added a deterministic edge-biased xorshift corpus comparing NTT + basemul + inverse NTT against an independent naive negacyclic-product oracle; CI evidence and broader independent FIPS/end-to-end correctness review remain pending.
- [ ] Add explicit target-feature detection/dispatch resolved once, plus `NEXUSQ_FORCE_SCALAR` test override.
- [ ] Differential tests compare every optimized kernel to scalar on random and edge/boundary inputs, bit-exactly.
- [ ] Every `unsafe` block in the optimized-kernel surface has a `// SAFETY:` justification; CI repository gate added at `.github/scripts/check-kernel-unsafe.py` and wired into `.github/workflows/ci.yml`, but acceptance awaits a green run on this PR head. `nexusq-core` remains `forbid(unsafe_code)`. The existing `nexusq-c` crate is a narrow C-ABI boundary and necessarily contains raw-pointer/FFI unsafe; audit that boundary separately, but do not put SIMD, assembly, or cryptographic kernel logic there.

## Phase 2 — Keccak/SHAKE

> Progress note for the current working PR: the AVX2 Keccak-f[1600] x4 and SHAKE128/SHAKE256 x4 source paths are present. FIPS 202 empty-input known-answer checks cover single-state and four-way SHAKE128/SHAKE256. Commit `444571d` adds a public incremental `api::Shake` wrapper with chunked absorb/finalize/squeeze; CI run [38541045920](https://github.com/lecodev-26/nexus-q/actions/runs/38541045920) passed Rust format/check/Clippy/tests/build/docs and secret scanning, including the incremental equivalence test. The overall run remains failed because the independent Arena performance gate is above 1.5x on multiple ML-KEM/ML-DSA operations; this API-only change is not claimed to improve those end-to-end ratios. `cargo audit` and `cargo deny` were skipped by repository configuration, and the long fuzz jobs were skipped on this V4 iteration. This phase remains open because single-state dispatch, optimized ARM paths, and top-level PQC integration are not complete.

- [ ] x86_64 AVX2 Keccak-f[1600] x4 and SHAKE128/SHAKE256 x4 for matrix expansion and sampling workloads.
- [ ] Evaluate a fast single-state BMI2/rotate path; AVX-512 is optional and separately dispatched, accepted only if end-to-end Arena data supports it without unacceptable downclocking.
- [ ] aarch64 ARMv8.2 SHA3 instructions and NEON x2, with portable fallback.
- [x] Provide a public incremental SHAKE absorb/finalize/squeeze interface with caller-owned output buffers. _Evidence: commit `444571d`; CI run `38541045920` passed the incremental-versus-one-shot test. Integration into PQC sampler buffers remains open._
- [ ] Validate against NIST SHAKE/SHA3 known-answer vectors and XKCP vectors.

## Phase 3 — ML-KEM (q = 3329)

- [ ] AVX2 NTT/inverse NTT with reviewed Montgomery/lazy Barrett arithmetic, fused layers where correct, pre-permuted zetas, and reduced copies.
- [ ] Fuse basemul and polyvec accumulation; optimize SampleNTT rejection sampling, CBD eta=2/3, compression/decompression, and packing/unpacking.
- [ ] Fuse keygen/encaps/decaps hot paths; FO re-encryption comparison and selection remain constant-time with no secret-dependent branches.
- [ ] Share kernels between ML-KEM-768 and ML-KEM-1024; verify the stated zero-allocation hot-path target with the profile harness rather than assumption.
- [ ] Implement and test corresponding aarch64 NEON paths.

## Phase 4 — ML-DSA (q = 8380417)

- [ ] AVX2 NTT/inverse NTT and reviewed `reduce32`/`caddq`/`freeze` arithmetic.
- [ ] Fuse pointwise and matrix-vector accumulation; keep A-hat in NTT domain where valid.
- [ ] Vectorize Power2Round, Decompose, HighBits/LowBits, MakeHint and UseHint.
- [ ] Vectorize packing for t1, t0, eta, z and w1; optimize rejection samplers and SampleInBall.
- [ ] Optimize signing norm checks/rejection loop without changing its security semantics; remove redundant secret expansion and allocations where measured.
- [ ] Optimize keygen/verify ExpandA using multi-state Keccak and avoid redundant decoding.
- [ ] Implement and test corresponding aarch64 NEON paths.

## Phase 5 — Integration

- [ ] Add `crates/nexusq-pqc` implementing FIPS 203/FIPS 204 flows over the kernels.
- [ ] Wire through a backend trait in `crypto::kem` and `crypto::pq_sign`; RustCrypto remains a selectable reference backend and safety net.
- [ ] Do not make the experimental backend default until correctness, security, and benchmark gates pass.
- [ ] Preserve public APIs, key/ciphertext/signature encodings, hybrid ML-KEM-768 + X25519 behavior, vault/envelope formats, and v1-created data compatibility.
- [ ] Preserve zeroization for stack/spilled secrets and address vector-register cleanup (`vzeroall`/`vzeroupper`) in any assembly path.

## Phase 6 — Correctness and security gates (blocking)

- [ ] NIST ACVP KATs for ML-KEM keygen/encaps/decaps and ML-DSA keygen/sign/verify for every used parameter set.
- [ ] Differential testing against RustCrypto and AWS-LC (Arena adapter), including invalid inputs and malformed encodings; retain reproducible corpus/results.
- [ ] Constant-time review and dudect-style timing tests; secret-poisoning/memcheck where supported; document permitted variable-time behavior (public rejection sampling and signing rejection loop only as justified).
- [ ] Long `cargo-fuzz` campaigns for each kernel and top-level operation; link run evidence and regression corpus. These are intentionally deferred during iterative V4 branch commits and must be completed as a release/security gate before final release/merge to `main`.
- [ ] Miri/sanitizers for scalar/safe code; ASan/UBSan for kernel tests where supported.
- [ ] Review every unsafe block and assembly routine; record findings and rationale in `docs/PQC_KERNELS.md` and an ADR.

## Phase 7 — Benchmark gate and iteration

- [ ] Run Arena after each phase and publish operation-by-operation ratios; prioritize the worst ratio, not the geometric mean alone.
- [ ] Profile with `perf`, cycle counters and `perf stat` (IPC/stalls); inspect generated assembly and register spills.
- [ ] Document micro-optimization experiments and reject changes without reproducible end-to-end evidence.
- [ ] Final performance gate: all nine operations <= 1.00x the best comparator in the same Arena run, across at least three independent reproducible runs, with no operation regressing above target.
- [ ] Keep cached ML-DSA verification results separate from conventional verification measurements.

## Phase 8 — Release hygiene

- [ ] CI matrix covers x86_64 AVX2 (and AVX-512 where available), aarch64, RISC-V scalar, and forced-scalar dispatch.
- [ ] Update `BENCHMARKS.md` from actual Arena data, `docs/CRYPTOGRAPHY.md`, threat model, and backend ADR (#7) to describe the new unsafe/assembly surface accurately.
- [ ] Attach JSONL, environment metadata, ratios, and run links to Issue #10; make no leadership claim without that evidence.
- [ ] Confirm API/wire-format compatibility, all security gates green, and no `unsafe` outside `nexusq-kernels`.

## Definition of done (all required)

- [ ] All nine operations are at or below 1.00x the best comparator in the same Arena run for at least three consecutive reproducible runs.
- [ ] All Phase 6 security/correctness gates pass; scalar fallback is tested in CI; `unsafe` is confined to `nexusq-kernels`.
- [ ] Public API and persistent/wire formats are unchanged; v1 data still opens.
- [ ] Evidence artifacts and operation-level ratio table are linked from Issue #10; docs and ADR are complete.
- [ ] Final PR review is complete and every CI check is green before merging this work into `nexusqv4`.

**Unsafe-code policy clarification:** the kernel crate is the only crate allowed to implement unsafe SIMD/assembly/cryptographic kernels. `nexusq-core` must continue to forbid unsafe code. The pre-existing `nexusq-c` crate is the separately audited C ABI boundary; its minimal raw-pointer operations are an explicit exception and must not grow into a kernel implementation.

## Working rules

1. Phase 0 blocks optimization claims and subsequent phase completion until measurement plumbing is proven.
2. Preserve V2/V3 branches and tags; do not modify `main` as part of V4 implementation.
3. Keep this PR targeted at `nexusqv4`. Once complete and green, merge into `nexusqv4`; only then open a separate review PR from `nexusqv4` to `main`.
4. Do not weaken zeroization, constant-time requirements, KATs, fuzzing, or release gates to improve speed. During iterative V4 development, `.github/workflows/ci.yml` skips all fuzz jobs on `v4/**`; the full fuzz soaks remain enabled on pushes to `main` and are required before final release. Existing fuzz-build behavior on PRs targeting `main` is preserved.
5. Every checked box must point to evidence in the PR, CI, or linked issue.
6. Persist all generated CI evidence for V4 under `artifact-archive/v4-issue23-measurement/<run-id>-<attempt>/` or `artifact-archive/v4-issue23-phase0/<run-id>-<attempt>/`; each run directory must include its provenance README and a run-local SHA-256 manifest. Evidence is archived once per commit by the `archive` job of `ci.yml`, only after Rust validation, security, secret scan, Phase 0 and measurement all pass; the bot commit carries `[skip ci]` and must not trigger another CI run.

### Diagnostic ratio report (source state reviewed 2026-10-12)

The measurement job captures CPU frequency/governor when the host exposes them and carries those values into both runners' JSONL records; unavailable frequency remains JSON `null` and an unavailable governor is recorded as `unknown`. Validation requires explicit metadata fields, checks Rust toolchain provenance and Cargo.lock SHA-256, and rejects malformed metadata. The schema now requires a machine-readable `comparison_contract`: the nine conventional FIPS operations use `fips_operation_v1`, while cached ML-DSA verification uses a separate diagnostic contract.

The matched-host measurement workflow emits `arena/results/v4-phase0/comparison-report.md` alongside raw JSONL. It lists median and p95 ratios for each algorithm/parameter/operation, excludes cached ML-DSA verification from the conventional gate, and treats missing operations or contract mismatches as failures. `measurement_scope` separately identifies the concrete implementation path; the AWS-LC adapter initializes reusable KEM contexts outside timed samples and measures public EVP operation calls, while retaining per-call sign/verify initialization required by the API. The `fips_operation_v1` contract is intended to compare the same FIPS operation at the public primitive-call boundary, not to erase implementation-specific costs. CI enforces the current 1.5x maximum on both median and p95 for every one of the nine operations against the pinned AWS-LC implementation measured on the same host. Cached verification is reported separately. This gate is implemented in source, but its performance outcome and the relevant C/API boundary behavior must be judged from evidence for the exact PR head. Do not infer a current CI conclusion from this document or from historical archived runs.


### Latest PR-head measurement (commit `444571d`, CI run `38541045920`)

The run generated 10 schema-valid NEXUS-Q records and 9 AWS-LC records, confirmed all nine conventional operation contracts and matched-host metadata, and passed ML-KEM self-checks before timing. The 1.5x median/p95 gate failed: ML-DSA-65 keygen median 5.809x / p95 6.189x; sign 4.568x / 3.928x; verify p95 1.622x. ML-KEM-1024 decaps 3.715x / 2.398x, encaps 3.929x / 4.415x, keygen 4.572x / 3.119x. ML-KEM-768 decaps 3.387x / 3.893x, encaps 3.508x / 3.700x, keygen 4.054x / 4.540x. Rust validation, documentation, and secret scanning passed. `cargo audit`/`cargo deny` were skipped and fuzz soak jobs were skipped for this V4 iteration; neither is counted as a passing security gate. This evidence does not accept Phase 0 or Issue #23.

### Latest PR-head measurement (commit `54e8596`, CI run `38596679241`)

Run: [38596679241](https://github.com/lecodev-26/nexus-q/actions/runs/38596679241). Rust format/check, Clippy, workspace tests, build, public docs, kernel unsafe-boundary audit, dependency-provenance check, and secret scanning passed. Both benchmark harnesses built and ran; ML-KEM self-checks passed. The validator confirmed 10 schema-valid NEXUS-Q records and 9 schema-valid AWS-LC records, all nine conventional operations, configured sample counts, and matched-host metadata. The run failed at the per-operation performance gate (not schema/coverage validation). With the unchanged 1.5x limit, ratios were: ML-DSA-65 keygen 5.840x median / 8.449x p95 and sign 4.931x / 4.330x; ML-KEM-1024 decaps 3.771x / 4.577x, encaps 3.930x / 6.709x, keygen 4.737x / 7.139x; ML-KEM-768 decaps 3.371x / 5.801x, encaps 3.457x / 4.102x, keygen 4.034x / 4.518x. The conventional ML-DSA verify ratio was not listed among the failed operations in this run; this does not establish the overall performance gate as passed. These results confirm that the current AVX2 x4 and incremental SHAKE APIs are not yet wired into the measured ML-KEM/ML-DSA operation paths. `cargo audit` and `cargo deny` were skipped by repository configuration; fuzz build/soak jobs were skipped on this V4 branch. Neither security audit nor fuzzing is counted as passing. No performance milestone or phase is accepted by this run. The uploaded raw measurement artifact is linked from the run.

# NEXUS-Q V4 — Issue #23 execution tracker

**Source of truth:** [Issue #23](https://github.com/lecodev-26/nexus-q/issues/23)  
**Working PR:** V4 implementation work targeting `nexusqv4`  
**Baseline:** `nexusqv4`, based on the reviewed V3 snapshot  
**Status:** Planning/tracking only. No cryptographic kernel is implemented by this commit.

This checklist mirrors the phases and acceptance criteria in Issue #23. Keep it updated in the working PR with links to commits, CI runs, benchmark artifacts, test evidence, and security review. Do not check an item merely because code exists; check it only after the evidence has been reviewed. Issue #23 remains open until its complete definition of done is met.

## Phase 0 — Trustworthy measurement (blocking)

- [ ] Make `arena/runners/nexusq` resolve the exact local kernel/backend source under development; prove it with `cargo tree -i ml-kem` (or the corresponding resolved dependency tree).
- [ ] Commit required vendored sources and patch configuration, or remove them; no untracked vendor/patch dependency.
- [ ] Benchmark all nine operations through the same primitive layer: ML-KEM-768/1024 keygen, encaps, decaps; ML-DSA-65 keygen, sign, verify.
- [ ] Use at least 1,000 measured iterations and 100 warmups; `black_box` inputs and outputs; report median, p95, and standard deviation.
- [ ] Record CPU model/features, governor, toolchain, build/profile and environment metadata in JSONL; compare implementations in the same CI job.
- [ ] Add cycle counts (`rdtsc`/`cntvct`) alongside wall-clock timing where supported, with a safe unsupported-platform fallback.
- [ ] Add a per-operation CI gate against the best comparator from the same run and the current milestone ratio: 1.5x → 1.2x → 1.05x → 1.00x.

## Phase 1 — Kernel crate skeleton

- [ ] Add `crates/nexusq-kernels`; it is the only crate permitted to contain `unsafe` code.
- [ ] Implement portable scalar reference kernels for NTT, inverse NTT, basemul/pointwise, reduce/freeze, compression/decompression, pack/unpack, CBD, rejection samplers, and Keccak-f[1600].
- [ ] Add explicit target-feature detection/dispatch resolved once, plus `NEXUSQ_FORCE_SCALAR` test override.
- [ ] Differential tests compare every optimized kernel to scalar on random and edge/boundary inputs, bit-exactly.
- [ ] Every `unsafe` block has a `// SAFETY:` justification; add CI auditing (`cargo geiger` and/or a repository gate).

## Phase 2 — Keccak/SHAKE

- [ ] x86_64 AVX2 Keccak-f[1600] x4 and SHAKE128/SHAKE256 x4 for matrix expansion and sampling workloads.
- [ ] Evaluate a fast single-state BMI2/rotate path; AVX-512 is optional and separately dispatched, accepted only if end-to-end Arena data supports it without unacceptable downclocking.
- [ ] aarch64 ARMv8.2 SHA3 instructions and NEON x2, with portable fallback.
- [ ] Streaming absorb/squeeze interface avoids unnecessary copies into sampler buffers.
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
- [ ] Long `cargo-fuzz` campaigns for each kernel and top-level operation; link run evidence and regression corpus.
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

## Working rules

1. Phase 0 blocks optimization claims and subsequent phase completion until measurement plumbing is proven.
2. Preserve V2/V3 branches and tags; do not modify `main` as part of V4 implementation.
3. Keep this PR targeted at `nexusqv4`. Once complete and green, merge into `nexusqv4`; only then open a separate review PR from `nexusqv4` to `main`.
4. Do not weaken zeroization, constant-time requirements, KATs, fuzzing, or release gates to improve speed.
5. Every checked box must point to evidence in the PR, CI, or linked issue.

# NEXUS-Q V4 — Issue #23 execution tracker

**Source of truth:** [Issue #23](https://github.com/lecodev-26/nexus-q/issues/23)  
**Working PR:** [#46](https://github.com/lecodev-26/nexus-q/pull/46), branch `v4/issue-23-kernel-work`, targeting `nexusqv4`

**Baseline:** reviewed V3 snapshot on `nexusqv4`

**Status (source audit 2026-10-15):** the Phase 0 measurement harness, shared operation-contract metadata, and per-operation median/p95 gate are present in the branch. The configured milestone is 1.5x, with fail-closed handling for missing operations, contract mismatch, malformed provenance, and ratio regressions. Phase 0 acceptance remains unchecked until the exact PR-head CI artifacts and comparison report have been reviewed; this tracker does not assert the outcome of the latest CI run. The scalar kernel crate is now present with Keccak-f[1600]/SHAKE128/SHAKE256 and ML-KEM reference operations including NTT/inverse NTT, basemul, reduction/normalization, compression/decompression, packing/unpacking, CBD, and rejection sampling. This is scalar reference groundwork only: independent end-to-end KAT/differential evidence, optimized SIMD/assembly kernels, complete security evidence, and phase acceptance remain open.

This checklist mirrors the phases and acceptance criteria in Issue #23. Keep it updated in the working PR with links to commits, CI runs, benchmark artifacts, test evidence, and security review. Do not check an item merely because code exists; check it only after the evidence has been reviewed. Issue #23 remains open until its complete definition of done is met.

## Phase 0 — Trustworthy measurement (blocking)

- [x] Make `arena/runners/nexusq` resolve the exact local kernel/backend source under development; prove it with `cargo tree -i ml-kem` (or the corresponding resolved dependency tree). _Evidence: `[patch.crates-io]` in `arena/runners/nexusq/Cargo.toml`; Phase 0 CI enforces vendor resolution (run 38123650717)._
- [x] Commit required vendored sources and patch configuration, or remove them; no untracked vendor/patch dependency. _Evidence: `vendor/ml-kem` and `vendor/module-lattice` are tracked together with the patch configuration._
- [ ] Benchmark all nine operations through the same primitive layer: ML-KEM-768/1024 keygen, encaps, decaps; ML-DSA-65 keygen, sign, verify. See [V4 Arena baseline audit](V4_ARENA_BASELINE_AUDIT.md) for the archived-result limitations.
- [x] Use at least 1,000 measured iterations and 100 warmups; `black_box` inputs and outputs; report median, p95, and standard deviation. _Evidence: [CI run 38648027975](https://github.com/lecodev-26/nexus-q/actions/runs/38648027975) — validator accepted raw samples/statistics and configured sample counts for all records._
- [x] Record CPU model/features, governor, toolchain, build/profile and environment metadata in JSONL; compare implementations in the same CI job. _Evidence: [CI run 38648027975](https://github.com/lecodev-26/nexus-q/actions/runs/38648027975) — schema/provenance validation accepted 10 NEXUS-Q and 9 AWS-LC records on the same host/job; unavailable governor/frequency are represented explicitly._
- [x] Add cycle counts (`rdtsc`/`cntvct`) alongside wall-clock timing where supported, with a safe unsupported-platform fallback. _Evidence: [CI run 38648027975](https://github.com/lecodev-26/nexus-q/actions/runs/38648027975) — x86_64 records contain TSC samples; schema permits explicit unavailable fallback._
- [x] Add a per-operation CI gate against the best comparator from the same run and the current milestone ratio: 1.5x → 1.2x → 1.05x → 1.00x. _Implementation evidence: workflow validates all nine operations and fails closed on median/p95 ratios over 1.5x; [CI run 38648027975](https://github.com/lecodev-26/nexus-q/actions/runs/38648027975) confirms the gate is active and failing. This marks implementation only, not Phase 0 acceptance._

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

### Latest PR-head measurement (commit `f99fe65`, CI run `38597338345`)

Run: [38597338345](https://github.com/lecodev-26/nexus-q/actions/runs/38597338345). The schema/coverage validator passed: 10 NEXUS-Q and 9 AWS-LC schema-valid records, all nine conventional operations, configured sample counts, and matched-host metadata. ML-KEM-768/1024 self-checks passed. Rust format/check, Clippy, workspace tests/build/docs, unsafe-boundary audit, dependency-provenance check, and secret scanning passed. The per-operation 1.5x median/p95 gate failed: ML-DSA-65 keygen 5.832x median / 5.227x p95; sign 4.945x / 4.027x; verify p95 1.623x. ML-KEM-1024 decaps 3.810x / 6.273x, encaps 4.043x / 4.488x, keygen 4.714x / 5.070x; ML-KEM-768 decaps 3.415x / 3.899x, encaps 3.554x / 4.179x, keygen 4.034x / 6.196x. The result is a performance-gate failure, not a schema/coverage failure. `cargo audit`/`cargo deny` and V4 fuzz jobs remain skipped and are not counted as passing.

Source review after this run confirms that `vendor/ml-kem/src/algebra.rs` performs the measured ML-KEM NTT/inverse-NTT and basemul through scalar `module-lattice` operations, while `crates/nexusq-kernels`'s polynomial kernels are separate reference functions and are not called by the measured backend. Likewise, `nexusq-kernels::api::Shake` is currently a scalar wrapper and is not wired into `vendor/ml-kem/src/crypto.rs`, whose SHAKE operations use the `sha3` crate. Do not claim these APIs improve Arena results until a production-path integration has bit-exact differential/KAT evidence and same-host measurements. The next implementation work must therefore target the actual vendored ML-KEM/ML-DSA hot paths and keep RustCrypto as a reference backend; simply adding more standalone kernels would not address this gate.

### Latest PR-head measurement (commit `14f96b9`, CI run `38598162647`)

Run: [38598162647](https://github.com/lecodev-26/nexus-q/actions/runs/38598162647). The schema/coverage validator passed: 10 NEXUS-Q and 9 AWS-LC schema-valid records, all nine conventional operations, configured sample counts, and matched-host metadata. ML-KEM-768/1024 encapsulation/decapsulation self-checks passed. Rust format/check, Clippy, workspace tests/build/docs, unsafe-boundary audit, dependency-provenance check, and secret scanning passed. The performance gate failed with the unchanged 1.5x median/p95 limit: ML-DSA-65 keygen 5.281x median / 4.964x p95, sign 3.751x / 3.301x; ML-KEM-1024 decaps 3.405x / 5.064x, encaps 3.518x / 6.002x, keygen 4.330x / 4.477x; ML-KEM-768 decaps 2.959x / 1.995x, encaps 3.039x / 3.297x, keygen 3.674x / 3.951x. The validator did not fail; the performance gate did. `cargo audit`/`cargo deny` were skipped because `ENABLE_SECURITY_AUDIT` is not enabled, and V4 fuzz jobs were skipped by branch policy. Neither is counted as passing. Evidence artifact: [download from run 38598162647](https://github.com/lecodev-26/nexus-q/actions/runs/38598162647/artifacts/11912890894).

### Latest PR-head measurement and hotspot profile (commit `0c94ad0`, CI run `38599530721`)

Run: [38599530721](https://github.com/lecodev-26/nexus-q/actions/runs/38599530721). Rust format/check, Clippy, workspace tests/build/docs, unsafe-boundary audit, dependency-provenance check, secret scanning, both benchmark harnesses, ML-KEM self-checks, and the new non-gating production-path profiler passed. Schema/coverage validation and all nine operation contracts passed; the run failed only at the unchanged 1.5x performance gate. Ratios: ML-DSA-65 keygen 5.231x median / 4.324x p95, sign 4.656x / 3.612x; ML-KEM-1024 decaps 2.603x / 2.393x, encaps 2.651x / 3.020x, keygen 3.370x / 3.128x; ML-KEM-768 decaps 2.553x / 2.572x, encaps 2.502x / 2.521x, keygen 2.997x / 3.033x. Conventional ML-DSA verify met both thresholds in this run; this does not pass the all-nine-operation gate. `cargo audit`/`cargo deny` remained skipped because security audit is not enabled, and V4 fuzz jobs remained skipped by branch policy.

The same-run diagnostic profile is in the [measurement artifact](https://github.com/lecodev-26/nexus-q/actions/runs/38599530721/artifacts/11912812390), file `profile-hotspots.txt`. Measured production-path results (2,000 iterations per workload) were: ML-KEM-768 keygen 32.2 µs / 5 allocations; encaps 27.0 µs / 1; decaps 32.8 µs / 0. ML-KEM-1024 keygen 52.5 µs / 5; encaps 42.8 µs / 0; decaps 50.8 µs / 0. ML-DSA-65 keygen 166.6 µs / 4; sign 86.9 µs / 3; conventional verify 101.6 µs / 3; cached verify 37.2 µs / 1. This is diagnostic evidence from one runner, not a speed claim or an acceptance result. The zero-allocation KEM encaps/decaps paths still miss the ratio gate, so allocation reduction alone is insufficient. Next work must integrate optimized kernels into the actual vendored production hot paths, beginning with measured shared arithmetic/hash bottlenecks; standalone kernels remain disconnected and cannot improve these figures by themselves.

### Latest PR-head measurement and hotspot profile (commit `0d96028`, CI run `38642772302`)

Run: [38642772302](https://github.com/lecodev-26/nexus-q/actions/runs/38642772302). Rust format/check, Clippy, workspace tests/build/docs, unsafe-boundary audit, dependency-provenance check, secret scanning, both benchmark harnesses, ML-KEM self-checks, and the non-gating production-path profiler passed. Schema/coverage validation passed with 10 schema-valid NEXUS-Q records and 9 AWS-LC records, all nine conventional operation contracts, configured sample counts, and matched-host metadata. The run failed at the unchanged 1.5x per-operation performance gate. Ratios from `comparison-report.md`: ML-DSA-65 keygen 6.135x median / 6.614x p95, sign 6.141x / 4.603x, verify 1.677x / 1.831x; ML-KEM-1024 decaps 3.190x / 3.474x, encaps 3.247x / 3.636x, keygen 3.882x / 4.142x; ML-KEM-768 decaps 2.881x / 3.249x, encaps 2.890x / 3.036x, keygen 3.492x / 3.520x. This run's ratios are worse than the preceding run on several operations; single-run variation must not be presented as a regression caused by the documentation-only commit. `cargo audit`/`cargo deny` were skipped because security audit is not enabled, and V4 fuzz jobs were skipped by branch policy; neither is counted as passing.

The raw records and diagnostic profile are in the [run artifact](https://github.com/lecodev-26/nexus-q/actions/runs/38642772302/artifacts). This evidence confirms the same root issue: production ML-KEM still routes NTT and polynomial arithmetic through scalar `module-lattice`, and the measured RustCrypto ML-DSA/ML-KEM operations do not consume the standalone AVX2 x4/experimental polynomial kernels. Phase 0 and Issue #23 remain unaccepted. Do not relax the threshold. The next implementation must introduce a narrow, auditable production-path integration with bit-exact differential tests before any performance claim; unsafe SIMD stays confined to `nexusq-kernels`, and the vendored cryptographic implementation remains the correctness reference until the experimental backend proves all correctness/security gates.

### Latest CI for tracker commit `2d663de` (run `38643496716`)

Run: [38643496716](https://github.com/lecodev-26/nexus-q/actions/runs/38643496716). Rust fmt/check, Clippy, workspace tests/build/docs, kernel `unsafe` boundary audit, dependency provenance, secret scanning, both benchmark harnesses, production-path profile, JSON schema validation, operation coverage, configured iteration/sample counts, same-host CPU/toolchain metadata, and ML-KEM shared-secret self-checks passed. The overall run failed only at the per-operation performance gate, not schema/coverage validation. At the unchanged 1.5x threshold, reported median/p95 ratios were: ML-DSA-65 keygen 5.808x/5.893x, sign 4.732x/4.006x, verify 1.000x/1.557x; ML-KEM-1024 decaps 3.160x/3.303x, encaps 3.269x/3.432x, keygen 3.894x/4.051x; ML-KEM-768 decaps 2.913x/3.088x, encaps 2.920x/3.300x, keygen 3.386x/3.561x. (Verify's median ratio is below the limit, but its p95 fails.) `cargo audit` and `cargo deny` were skipped because the security-tooling switch is disabled; V4 fuzz jobs were skipped by branch policy. These are not passes. Phase 0 and Issue #23 remain open/unaccepted.

The schema/coverage step's display name includes schema validation, but the logs explicitly show both datasets schema-valid and all expected operations present; the failing assertion is the subsequent performance gate. No threshold, sample count, or comparison contract was weakened. Production optimization/integration is still outstanding; the previous commits in this sequence were evidence/documentation only and must not be described as performance fixes.


### Latest PR-head audit (commit `d7fcc3f`, CI run `38648027975`)

Run: [38648027975](https://github.com/lecodev-26/nexus-q/actions/runs/38648027975). The dependency-provenance check, secret scan, and security/cargo-audit/cargo-deny/SBOM-input job passed. The kernel unsafe-policy script passed. The Rust validation job failed in `cargo clippy --workspace --all-targets --locked -- -D warnings` on two `clippy::needless_range_loop` diagnostics in `crates/nexusq-kernels/src/api.rs` (the loops in `ShakeX4::absorb`, around lines 69 and 72); this is a lint failure, not a reported algorithmic test failure. `cargo check --workspace --all-targets --locked` completed first. The Arena runner completed its operation measurements and emitted schema-valid JSONL (10 NEXUS-Q records including separately reported cached verification; 9 AWS-LC records), with all nine conventional operation records and configured sample counts. The 1.5x median/p95 gate failed. Median ratios over 1.5x: ML-DSA-65 keygen 5.798x, sign 4.991x; ML-KEM-1024 keygen 4.715x, encaps 4.065x, decaps 3.817x; ML-KEM-768 keygen 4.267x, encaps 3.670x, decaps 3.523x. P95 also failed for these operations, and additionally ML-DSA-65 verify (1.632x p95). The archive job skipped because the complete gate did not pass. The benchmark run does not demonstrate an improvement attributable to SHAKE x4: there is no accepted before/after matched-run analysis, and the measured ML-KEM operation ratios remain materially above the gate.

**Source audit outcome:** `vendor/ml-kem/src/algebra.rs` now routes batched matrix sampling through `ShakeX4` under the `nexusq-kernels` feature, but its NTT, inverse NTT and basemul arithmetic still use scalar `module-lattice` operations. ML-DSA remains the external `ml-dsa 0.1.1` dependency and has no NEXUS-Q optimized-kernel integration. The x4 AVX2 permutation is in `crates/nexusq-kernels/src/x86_64/avx2.rs`; runtime fallback exists, but the overall dispatch still selects scalar for single-state operations. No NTT/INTT AVX2, ML-DSA SIMD, aarch64 NEON/SHA3 path, or justified inline assembly is accepted by this audit. FIPS/ACVP end-to-end KAT coverage, broad differential corpora, dudect/timing, long fuzz, Miri/sanitizer and external cryptographic audit remain open. No performance milestone or phase acceptance is inferred from code presence alone.

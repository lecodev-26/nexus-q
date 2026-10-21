# Issue #71 — native ML-KEM/ML-DSA production-path integration

## Implementation state

The opt-in native backend is already wired into the real `nexusq-core` ML-KEM-768/1024, hybrid X-Wing, and ML-DSA-65 call paths. The public build feature is `native-backend`; `native-backend-portable` selects the native libraries' portable C implementation. Both are explicit opt-ins. The default build remains RustCrypto, and no CLI, server, C/Python binding, or SDK silently enables the native backend. See [`../performance/NATIVE_BACKEND_PRODUCTION_WIRING.md`](../performance/NATIVE_BACKEND_PRODUCTION_WIRING.md) for architecture and historical CI benchmark evidence.

This issue pass revalidated that integration locally without enabling it by default. The implementation is described as *experimental native code with constant-time validation evidence*, not as independently audited or proven constant-time.

## Local verification on the 4.1.1 work branch

The following commands completed successfully on the local worktree:

- `cargo test --workspace` — exit 0; all executed workspace tests and doctests passed (one cross-configuration test is intentionally ignored by the normal suite and is run separately by CI).
- `cargo test -p nexusq-core --features native-backend --locked` — 569 tests passed, 0 failed; native ML-KEM-768/1024 and ML-DSA interoperability tests passed.
- `cargo test -p nexusq-core --features native-backend-portable --locked` — 569 tests passed, 0 failed.
- `cargo check -p nexusq-cli -p nexusq-server -p nexusq-c -p nexusq-py --features native-backend --locked` — passed.
- The same SDK check with `--features native-backend-portable --locked` — passed.
- `cargo test --manifest-path crates/nexusq-native-backend/Cargo.toml --locked --release`, plus the `portable-only` and `upstream-c-keccak` variants — each passed the native-backend unit tests and all three differential tests (ML-KEM-768, ML-KEM-1024, ML-DSA-65).
- `cargo clippy --manifest-path crates/nexusq-native-backend/Cargo.toml --locked --all-targets --release -- -D warnings` — passed.
- `crates/nexusq-native-backend/ct/run.sh /tmp/nexusq-ct-issue71` — passed locally. Valgrind memcheck reported zero errors; the deliberate secret-dependent negative control was detected; Callgrind confirmed the expected AVX2 and Keccak assembly symbols executed.
- `cargo clippy -p nexusq-admin -p nexusq-pki-cluster --all-targets -- -D warnings` — passed as part of the preceding local work.

## Gates that remain distinct from local validation

- The required multi-hour fuzz soaks must be run and confirmed green on the exact release candidate SHA. They were not run as part of this local pass.
- The 1.5× median-and-p95 production-path benchmark evidence documented in `NATIVE_BACKEND_PRODUCTION_WIRING.md` is historical CI evidence for its recorded commit. It was not re-created by this local pass; do not describe it as a fresh benchmark of the current SHA.
- Valgrind/ctgrind catches some secret-dependent branches and memory accesses but cannot prove constant-time behavior or detect every variable-latency instruction.
- The independent external audit remains open. No FIPS 140-3 validation or general production-readiness claim follows from these tests.

## Rollout policy

Keep RustCrypto as the default. Keep the native implementation opt-in until the exact candidate passes the required CI/fuzz/performance gates and the independent security review is resolved. No package version was bumped and no artifact was published as part of this work.

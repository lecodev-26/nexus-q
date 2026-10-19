# Experimental native backend feature

The native backend is opt-in and experimental. The default `nexusq-core` build continues to use the existing RustCrypto implementation. The feature must not be enabled in published packages or production deployments until the Phase 21 independent external audit is complete. The PR #55 engineering review is done and the CI gates are green on its final head; the two four-hour fuzz soaks remain to be executed and confirmed green on the exact SHA that gets merged (maintainer's responsibility, before merge), and none of this is an independent audit.

## Enable for local evaluation

From the repository root:

```sh
cargo test -p nexusq-core --features native-backend --locked
cargo test -p nexusq-core --features native-backend-portable --locked
```

- `native-backend` builds the native C backend; on supported x86-64 Linux hosts its assembly path is runtime-dispatched, otherwise the backend uses its portable C path.
- `native-backend-portable` forces the backend's portable C implementation for evaluation. It is not the same as the default RustCrypto fallback: omit both features to use RustCrypto.
- The feature currently routes ML-KEM-768/1024 encapsulation and decapsulation and ML-DSA-65 signing and verification through the native backend. Other primitives remain on their existing implementation.
- Public Rust API shapes and serialized key/ciphertext/signature formats are intended to remain unchanged. CI differential/interoperability tests are required to substantiate that claim.
- ML-DSA native signing is hedged with fresh OS randomness; do not assume signatures are byte-for-byte deterministic.

## Release restrictions

This feature is not enabled by default. The PR #55 correctness, FFI/security, portability, production-path benchmark and 1.5x median-and-p95 gates have been reviewed and are green on the final head; the fuzz-harness gates are green and the two four-hour soak verdicts are pending (they must be executed and confirmed on the exact SHA that gets merged; the maintainer does this before merge). The production-path benchmark evidence is linked in [`NATIVE_BACKEND_PRODUCTION_WIRING.md`](NATIVE_BACKEND_PRODUCTION_WIRING.md) and the gate re-runs on every PR head through the Native Backend Gate. The feature remains opt-in: it is not enabled in the CLI, the server or published SDK build profiles, and production readiness is still not claimed — the Phase 21 independent external audit remains open. The isolated backend benchmark is not a substitute for measuring production call paths; the production-path benchmark evidence is recorded in the PR #55 master-checklist comment.

## Known limitations

- **AArch64**: the native assembly path (including any NEON specialization) is not enabled on AArch64; AArch64 hosts run the backend's portable C path, which is functionally tested. No AArch64 performance numbers are claimed or measured here.
- **Unsupported targets**: when the feature is off, every target uses RustCrypto exactly as before. When the feature is on, non-x86-64 or non-Linux targets build the backend's portable C path; the x86-64 assembly path is runtime-dispatched and safely falls back to portable C when AVX2/BMI2 are unavailable.
- **Valgrind harness limitation**: the constant-time harness is one contributing assurance signal, not a complete constant-time proof (see [`NATIVE_BACKEND.md`](NATIVE_BACKEND.md)).
- **No FIPS 140-3 validation and no PCT** is run, matching the non-FIPS AWS-LC comparator build.
- **ML-DSA determinism**: native signing is hedged with fresh OS randomness; signatures are not byte-for-byte deterministic.

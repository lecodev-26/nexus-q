# Experimental native backend feature

The native backend is opt-in and experimental. The default `nexusq-core` build continues to use the existing RustCrypto implementation. Do not enable this feature in published packages or production deployments until PR #55 is reviewed and all required gates pass.

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

This feature is not enabled by default. Do not merge the integration, enable it in CLI/SDK build profiles, publish crates or packages, or claim production readiness until correctness, FFI/security, portability, fuzzing, production-path benchmark, and the 1.5x median-and-p95 gates are reviewed. The isolated backend benchmark is not a substitute for measuring these production call paths.

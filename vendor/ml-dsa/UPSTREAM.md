# Vendored ML-DSA provenance

- Upstream project: RustCrypto/signatures, crate `ml-dsa`.
- Crate version: `0.1.1`.
- Upstream revision: `f75d5b829948988f18d9463f286805fb9410bcdd`.
- Upstream repository: https://github.com/RustCrypto/signatures/tree/f75d5b829948988f18d9463f286805fb9410bcdd/ml-dsa
- License: Apache-2.0 OR MIT. The upstream `LICENSE-APACHE` and `LICENSE-MIT` files are retained.

## Local changes

The following local changes are present:

| File | Change | Feature gate | Default-build status |
|---|---|---|---|
| `src/ntt.rs` | Kernel integration for NTT-related operations | `experimental-kernels` | Upstream arithmetic path is used by default |
| `src/sampling.rs` | Kernel integration for sampling operations | `experimental-kernels` | Upstream sampling path is used by default |
| `src/lib.rs` | Test-only formatting changes in the crate copy | None | Test-only; no production behavior change |

The `ntt.rs` and `sampling.rs` changes are present in both the vendor and crate copies. The test-only `lib.rs` changes are present in the crate copy.

## Rules for future changes

Do not claim performance improvements from vendoring alone. Keep upstream attribution and license files with any later modifications. Record each local patch in this file, including the affected file, change, feature gate, and default-build status.

The corresponding vendor snapshot is maintained in `vendor/ml-dsa`. Keep this provenance record synchronized with the crate copy.

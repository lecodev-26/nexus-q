# Vendored ML-KEM provenance

- Upstream project: RustCrypto/KEMs, crate `ml-kem`.
- Crate version: `0.3.2`.
- Upstream revision (from `.cargo_vcs_info.json`): `440768245bba59784b504269cb3087a6c21af45c`.
- Upstream repository: https://github.com/RustCrypto/KEMs/tree/440768245bba59784b504269cb3087a6c21af45c/ml-kem
- License: Apache-2.0 OR MIT; the upstream `LICENSE-APACHE` and `LICENSE-MIT` files are retained.

## Local patches

Compared with upstream `ml-kem` 0.3.2 @ `4407682`, six files under `src/` differ
(+357/-34, identical in `vendor/ml-kem` and `crates/nexusq-ml-kem`).

| File | Local change | Default build |
|------|--------------|---------------|
| `src/algebra.rs` | `matrix_sample_ntt` restructured; new `sample_ntt_x4`; kernel routing for NTT, inverse NTT and `MultiplyNTTs` | Restructuring is **active**. Kernel routing is gated behind `experimental-kernels` and is **inactive**. |
| `src/param.rs` | Extra `K: Mul<K>` and `Prod<K, K>: ArraySize` bounds on the public traits `ParameterSet` and `PkeParams` | **Active** (not feature-gated) |
| `src/compress.rs` | Fully qualified `Truncate` call | **Active**; no behavior change |
| `src/pke.rs` | New `from_generated_*` constructor(s), absent upstream | **Active** (always compiled) |
| `src/encapsulation_key.rs` | New `EncapsulationKey::from_generated_bytes` (`pub` + `#[doc(hidden)]`) | **Active** (always compiled) |
| `src/decapsulation_key.rs` | New `DecapsulationKey::from_generated_expanded_bytes` and `..._with_public` (`pub` + `#[doc(hidden)]`) | **Active** (always compiled) |

### `from_generated_*` constructors: security note

These constructors are local additions and are not present in upstream
RustCrypto ML-KEM. They bypass the FIPS 203 §7.2 modulus check and the
public-key hash check.

They are intended only for keys produced by a trusted generator and must
never be used with untrusted input.

The constructors are compiled regardless of the `native-backend` feature.
Their current callers are in `nexusq-core` (`crypto/kem.rs` and
`crypto/kem_1024.rs`), where the calls are gated behind `native-backend`.

### Feature gates

- `nexusq-kernels` only adds the `nexusq-kernels` dependency.
- `experimental-kernels` gates every call into `nexusq_kernels::`
  (`src/algebra.rs`). The kernels are correctness-oriented reference code, not a
  constant-time production implementation.

## Reproducing the diff

    diff -ru <upstream>/ml-kem/src <fork>/src | diffstat

## Rules for future changes

Keep upstream attribution and license files, and record each local patch in this
file (file, change, feature gate, default-build status).

The corresponding vendor snapshot is maintained in `vendor/ml-kem`.
Keep this provenance record synchronized with the vendor copy.

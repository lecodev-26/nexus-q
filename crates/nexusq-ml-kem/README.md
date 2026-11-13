# nexusq-ml-kem

ML-KEM (FIPS 203, formerly known as Kyber) as used by [NEXUS-Q](https://github.com/lecodev-26/nexus-q).

This is a fork of the pure Rust [RustCrypto `ml-kem`](https://github.com/RustCrypto/KEMs) implementation
(vendored at version 0.3.2 in the NEXUS-Q repository). It includes optional
integration points for the NEXUS-Q scalar reference kernel set. These are
activated only with the `experimental-kernels` feature. The library target
name remains `ml_kem`, so code written against the upstream crate keeps compiling.

The upstream license (Apache-2.0 OR MIT) is preserved; see `LICENSE-APACHE` and
`LICENSE-MIT`. Local modifications relative to upstream are recorded in
[`UPSTREAM.md`](UPSTREAM.md).

## Usage

```toml
[dependencies]
nexusq-ml-kem = "4.1.2"
```

## Features

| Feature | Effect |
|---------|--------|
| `nexusq-kernels` | Only adds the `nexusq-kernels` dependency (`dep:nexusq-kernels`). It does **not** change which arithmetic runs. |
| `experimental-kernels` | Actually routes NTT, inverse NTT and `MultiplyNTTs` to the `nexusq-kernels` implementations. |

**Default builds use the upstream RustCrypto arithmetic implementations.**
Some local structural and compatibility changes remain active in all builds;
see `UPSTREAM.md` for details.

With only `nexusq-kernels` enabled, the kernel crate is compiled and linked
but its implementations are not called. To run the kernels, enable
`experimental-kernels` as well.

`experimental-kernels` is experimental: the kernels are correctness-oriented
reference code, not a constant-time production implementation (see the
`nexusq-kernels` README). Do not rely on them for production secrets.

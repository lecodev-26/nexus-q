# nexusq-ml-dsa

ML-DSA (FIPS 204, formerly known as CRYSTALS-Dilithium) as used by [NEXUS-Q](https://github.com/lecodev-26/nexus-q).

This is a fork of the pure Rust [RustCrypto `ml-dsa`](https://github.com/RustCrypto/signatures)
implementation (vendored at version 0.1.1 in the NEXUS-Q repository). It includes
optional integration points for the NEXUS-Q scalar reference kernel set. These
are activated only with the `experimental-kernels` feature. The library target
name remains `ml_dsa`, so code written against the upstream crate keeps compiling.

The upstream license (Apache-2.0 OR MIT) is preserved; see `LICENSE-APACHE` and
`LICENSE-MIT`. Local modifications relative to upstream are recorded in
[`UPSTREAM.md`](UPSTREAM.md). Upstream changes are tracked in the `vendor/ml-dsa`
snapshot of the NEXUS-Q repository and merged here.

## Usage

```toml
[dependencies]
nexusq-ml-dsa = "4.1.2"
```

## Features

| Feature | Effect |
|---------|--------|
| `nexusq-kernels` | Only adds the `nexusq-kernels` dependency (`dep:nexusq-kernels`). It does **not** change which arithmetic runs. |
| `experimental-kernels` | Actually routes NTT / inverse NTT (`src/ntt.rs`) and sampling (`src/sampling.rs`) to the `nexusq-kernels` implementations. |

**Default builds use the upstream RustCrypto arithmetic implementations.**
The local NTT and sampling kernel integrations are activated only with
`experimental-kernels`. Some local structural changes are also documented
in `UPSTREAM.md`.

With only `nexusq-kernels` enabled, the kernel crate is compiled and linked
(requires `nexusq-kernels` from crates.io) but its implementations are not
called. To run the kernels, enable `experimental-kernels` as well:

```toml
[dependencies]
nexusq-ml-dsa = { version = "4.1.2", features = ["nexusq-kernels", "experimental-kernels"] }
```

`experimental-kernels` is experimental: the kernels are correctness-oriented
reference code, not a constant-time production implementation (see the
`nexusq-kernels` README). Do not rely on them for production secrets.

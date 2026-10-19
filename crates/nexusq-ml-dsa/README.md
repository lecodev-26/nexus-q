# nexusq-ml-dsa

ML-DSA (FIPS 204, formerly known as CRYSTALS-Dilithium) as used by [NEXUS-Q](https://github.com/lecodev-26/nexus-q).

This is a fork of the pure Rust [RustCrypto `ml-dsa`](https://github.com/RustCrypto/signatures)
implementation (vendored at version 0.1.1 in the NEXUS-Q repository), adding an
optional `nexusq-kernels` feature that wires the NEXUS-Q audited scalar kernel
set (`nexusq-kernels`) into the arithmetic hot paths. The library target name
remains `ml_dsa`, so code written against the upstream crate keeps compiling.

The upstream license (Apache-2.0 OR MIT) is preserved; see `LICENSE-APACHE` and
`LICENSE-MIT`, and `UPSTREAM.md` for the fork relationship. Upstream changes are
tracked in the `vendor/ml-dsa` snapshot of the NEXUS-Q repository and merged here.

## Usage

```toml
[dependencies]
nexusq-ml-dsa = "4.1.0"
```

Enable the NEXUS-Q kernels with the `nexusq-kernels` feature (requires
`nexusq-kernels` from crates.io).

# nexusq (metacrate)

One dependency for the complete [NEXUS-Q](https://github.com/lecodev-26/nexus-q) Rust library stack.

```bash
cargo add nexusq
```

This adds — and lets Cargo download and compile — the separately published
NEXUS-Q library crates:

| Crate | Role |
|---|---|
| `nexusq-core` | Core library: vault, identity, policy, crypto (depends on the crates below) |
| `nexusq-kernels` | Portable scalar reference kernels and audited dispatch boundary |
| `nexusq-ml-kem` | ML-KEM (FIPS 203) key encapsulation |
| `nexusq-ml-dsa` | ML-DSA (FIPS 204) signatures |

The crates remain independent on crates.io; this package only groups them so
`cargo add nexusq` works as a single command.

## Usage

```rust
use nexusq::prelude::*;
```

The prelude mirrors `nexusq-core`'s. Each component is also reachable as a
module (`nexusq::nexusq_core`, `nexusq::nexusq_ml_kem`, ...).

## Notes

- The CLI and server are binary crates (`cargo install nexusq-cli`,
  `cargo install nexusq-server`) and are not part of this dependency.
- Prefer a minimal dependency tree? Add the individual crates instead
  (e.g. `cargo add nexusq-core`).
- Post-quantum engine: ML-KEM/ML-DSA, hybrid X25519, AES-GCM/ChaCha20
  ciphersuites. See the repository documentation for the security posture
  and validation status.

License: MIT OR Apache-2.0.

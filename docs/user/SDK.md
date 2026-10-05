# SDK Guide

All SDKs are wrappers around the same Rust core. They do not reimplement cryptography.

## Current bindings

| Binding | Boundary | Current local surface |
|---|---|---|
| Rust | native crate | full core API |
| C | C ABI | vault/version surface documented by the C SDK |
| C++ | C++17 wrapper over C | vault/version surface |
| Python | PyO3 | vault/version surface |
| Go | cgo over C | vault/version surface |
| Ruby | FFI over C | vault/version surface |
| PHP | FFI over C | vault/version surface |

See each binding's README for its exact current API and toolchain requirements.

## Native build

Build the C library:

```bash
cargo build -p nexusq-c
```

This produces the native library used by the C-ABI family.

Python development builds use maturin:

```bash
cd crates/nexusq-py
maturin develop
```

## Important boundary

The existence of a binding in the repository does not mean it has already been published to a package registry. Publication is a Phase 22/release process gate.

TypeScript/Java/Kotlin/C#/Swift/Dart remain CI/release-scope work rather than claiming local availability.

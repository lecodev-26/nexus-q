# SDK Guide

The shipped bindings wrap the same Rust core and do not reimplement cryptography. The current repository ships C and limited Python bindings; other language SDKs are not claimed as available.

## Current bindings

| Binding | Boundary | Current local surface |
|---|---|---|
| Rust | native crate | full core API |
| C | C ABI | vault/version surface documented by the C SDK |
| Python | PyO3 | version and limited vault surface |

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

The existence of a binding in the repository does not mean it has already been published to a package registry. V2.0.0 GitHub release and downstream Rust/Python/SDK publication are separate release gates; registry publication is not implied by repository presence.

TypeScript/Java/Kotlin/C#/Swift/Dart remain CI/release-scope work rather than claiming local availability.

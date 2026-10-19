# SDK Guide

The shipped bindings wrap the same Rust core and do not reimplement cryptography. The repository ships C, Python, Go, PHP, Ruby, TypeScript, Java, Kotlin, C#/.NET, Swift and Dart bindings; every binding except the Python one (PyO3 native extension) and the Rust crates is a thin FFI wrapper over the C SDK.

## Current bindings

| Binding | Boundary | Current local surface |
|---|---|---|
| Rust | native crate | full core API |
| C | C ABI | vault/version surface documented by the C SDK |
| Python | PyO3 | version and limited vault surface |
| Go | cgo over the C SDK | vault/version surface |
| PHP | FFI over the C SDK | vault/version surface |
| Ruby | FFI over the C SDK | vault/version surface |
| TypeScript / Node.js | koffi FFI over the C SDK | vault/version surface |
| Java | JNA over the C SDK | vault/version surface |
| Kotlin | JNA over the C SDK | vault/version surface |
| C# / .NET | P/Invoke over the C SDK | vault/version surface |
| Swift | SPM system-library target over the C SDK | vault/version surface |
| Dart | dart:ffi over the C SDK | vault/version surface |

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

The existence of a binding in the repository does not mean it has already been published to a package registry. Registry publication is not implied by repository presence: check the installation table in [INSTALLATION.md](INSTALLATION.md) for the current publication status of each channel.

The FFI bindings expose the operations the C SDK currently publishes (version, last error, vault creation and format version). More operations land as the C SDK grows; the bindings are intentionally thin so that no cryptography or business logic is duplicated outside the Rust core.

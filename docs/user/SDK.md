# SDK Guide

The shipped bindings wrap the same Rust core and do not reimplement cryptography. The repository ships C, Python, Go, PHP, Ruby, TypeScript, Java, Kotlin, C#/.NET, Swift and Dart bindings; every binding except the Python one (PyO3 native extension) and the Rust crates is a thin FFI wrapper over the C SDK.

## Current bindings

| Binding | Boundary | Current local surface |
|---|---|---|
| Rust | native crate | full core API |
| C | C ABI | vault/version and provider metadata |
| C++ | header-only C ABI wrapper | vault/version and provider metadata |
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


## Cryptographic provider reporting

The core API exposes `nexusq_core::backend_info()`. The CLI reports the same
compile-time choice with `nexusq backend` and includes it in health/diagnostics
JSON. The server exposes the provider in `/health` and `/v1/health`. The C ABI
provides `nexusq_backend_name()` and `nexusq_backend_is_experimental()`, and
Python provides `nexusq.backend_info()`. These report the provider compiled into
the binary; they do not switch it at runtime. RustCrypto remains the default.
The native provider is experimental and must be explicitly selected at build
time with `native-backend`; packaged releases must not enable it implicitly.

For an explicitly opted-in engineering build, enable the same feature on the
entry point being built (the default remains RustCrypto):

```bash
cargo build -p nexusq-cli -p nexusq-server -p nexusq-c --features native-backend
cargo run -p nexusq-cli --features native-backend -- backend --output json
```

Use `native-backend-portable` instead to exercise the portable C implementation
without x86-64 assembly. The provider is selected at build time; a runtime
request cannot silently switch implementations.


## Native C ABI runtime artifact targets

The native-runtime CI/release workflow currently builds version-matched artifacts
for `x86_64-unknown-linux-gnu` (runtime-dispatched x86-64 native path),
`aarch64-unknown-linux-gnu` (portable C path), `aarch64-apple-darwin` (portable
C path), and `x86_64-pc-windows-msvc` (portable C path). The artifact contains
`libnexusq`, `nexusq.h`, a target/provider manifest, and SHA-256 checksums.
Other OS/architecture/ABI combinations are not declared as prebuilt-runtime
targets by this workflow; SDKs must not substitute a binary from another target.
The RustCrypto provider remains the default for ordinary builds. These native
artifacts are explicitly experimental and do not imply an independent audit or
production-readiness approval.

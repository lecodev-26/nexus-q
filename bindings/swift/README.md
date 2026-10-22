# NEXUS-Q Swift SDK

Swift bindings for NEXUS-Q. A thin wrapper over the
[C SDK](../../crates/nexusq-c) through a version-matched dynamic runtime.
It does not reimplement anything: every call goes through `libnexusq`.

## Requirements

- Swift 5.9 or newer on macOS 12+.
- Published releases automatically download the version-matched RustCrypto
  runtime and verify its SHA-256 checksum on macOS ARM64. The runtime is cached
  under `~/.cache/nexusq/<version>/<runtime-asset>`; Rust is not required.
- macOS Intel and non-Apple targets are not currently supported by the prebuilt
  runtime. `NEXUSQ_LIBRARY` remains an advanced override for a compatible build.

## Usage

```swift
import Nexusq

print("nexusq version: \(Nexusq.version())")

let vault = try Nexusq.Vault.create("my.nqv", password: "password", label: "my-label")
print("vault created at \(vault.path)")
print("format version: \(vault.formatVersion)")
```

`Vault.create` throws `Nexusq.NexusqError` with the library's last error
message when an operation fails.

## What is available

- `Nexusq.version()` — returns the library version.
- `Nexusq.lastError()` — returns the last C SDK error message.
- `Nexusq.Vault`:
  - `Vault.create(path, password:, label:)` — creates a new vault.
  - `vault.path` — returns the vault file path.
  - `vault.formatVersion` — returns the format version.

More operations land as the C SDK grows.

## Testing

Run the smoke test and the XCTest suite from the repository root:

```bash
cd bindings/swift
NEXUSQ_LIBRARY=../../target/debug/libnexusq.dylib swift run Smoke
NEXUSQ_LIBRARY=../../target/debug/libnexusq.dylib swift test
```

The Swift binding is intentionally a thin wrapper over the C SDK, matching
the Go SDK architecture. No cryptography or business logic is duplicated
in Swift.

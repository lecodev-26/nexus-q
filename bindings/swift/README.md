# NEXUS-Q Swift SDK

Swift bindings for NEXUS-Q. A thin wrapper over the
[C SDK](../../crates/nexusq-c) exposed through Swift Package Manager's
`CNexusq` system-library target. It does not reimplement anything: every
call goes through `libnexusq`.

## Requirements

- Swift 5.9 or newer.
- The C SDK built and *installed* so the linker and the dynamic loader can
  find it (`cargo build -p nexusq-c`, then `LD_LIBRARY_PATH=target/debug`
  from the repository root).
- On Apple platforms, install `libnexusq.dylib` into a standard library
  path (for example `/usr/local/lib`).

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
LD_LIBRARY_PATH=target/debug swift run Smoke
LD_LIBRARY_PATH=target/debug swift test
```

The Swift binding is intentionally a thin wrapper over the C SDK, matching
the Go SDK architecture. No cryptography or business logic is duplicated
in Swift.

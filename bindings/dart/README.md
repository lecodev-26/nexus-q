# NEXUS-Q Dart SDK

Dart bindings for NEXUS-Q. A thin `dart:ffi` wrapper over the stable C ABI (`libnexusq`); it does not reimplement cryptography or business logic.

## Requirements

- Dart 3 or newer.
- Dart 3 or newer and `curl` on supported targets.
- Network access on first use; the SDK downloads the 4.1.1 runtime, verifies its SHA-256 checksum, and caches it per user/version. No C compiler or manually configured library path is required.
- Prebuilt targets: Linux x64/ARM64 with glibc, macOS ARM64, and Windows x64. Linux musl/Alpine and other unsupported targets require a compatible custom runtime.

## Usage

```dart
import 'package:nexusq/nexusq.dart';

void main() {
  print('nexusq version: ${version()}');

  final vault = Vault.create('my.nqv', 'password', label: 'my-label');
  print('vault created at ${vault.path}');
  print('format version: ${vault.formatVersion}');
}
```

Run normally; the first call resolves and verifies the runtime automatically:

```bash
dart run your_program.dart
```

`NEXUSQ_LIBRARY` remains an advanced override for development and offline tests.

## What is available

- `version()` — returns the library version.
- `lastError()` — returns the last C SDK error message.
- `Vault`:
  - `Vault.create(path, password, {label})` — creates a new vault.
  - `vault.path` — returns the vault file path.
  - `vault.formatVersion` — returns the format version.
- `NexusqException` — the exception thrown on failures.

More operations land as the C SDK grows.

## Testing

Run the smoke test and the unit suite from the repository root:

```bash
cd bindings/dart
NEXUSQ_LIBRARY=../../target/debug/libnexusq.so dart run example/smoke.dart
NEXUSQ_LIBRARY=../../target/debug/libnexusq.so dart test
```

The Dart binding is intentionally a thin wrapper over the C ABI. No cryptography or business logic is duplicated in Dart.

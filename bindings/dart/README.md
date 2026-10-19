# NEXUS-Q Dart SDK

Dart bindings for NEXUS-Q. A thin wrapper over the
[C SDK](../../crates/nexusq-c) using `dart:ffi`. It does not reimplement
anything: every call goes through `libnexusq`.

## Requirements

- Dart 3 or newer.
- The C SDK built (`cargo build -p nexusq-c`).
- `libnexusq.so` available at runtime through `LD_LIBRARY_PATH` or
  `NEXUSQ_LIBRARY`.

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

Run with:

```bash
NEXUSQ_LIBRARY=/path/to/nexusq/target/debug/libnexusq.so dart run your_program.dart
```

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
NEXUSQ_LIBRARY=target/debug/libnexusq.so dart run bindings/dart/example/smoke.dart
NEXUSQ_LIBRARY=target/debug/libnexusq.so dart test bindings/dart
```

The Dart binding is intentionally a thin wrapper over the C SDK, matching
the Go SDK architecture. No cryptography or business logic is duplicated
in Dart.

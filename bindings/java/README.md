# NEXUS-Q Java SDK

Java bindings for NEXUS-Q. A thin wrapper over the
[C SDK](../../crates/nexusq-c) using [JNA](https://github.com/java-native-access/jna).
It does not reimplement anything: every call goes through `libnexusq`.

## Requirements

- Java 11 or newer.
- Maven 3.6 or newer (to build).
- The C SDK built (`cargo build -p nexusq-c`).
- `libnexusq.so` available at runtime through `LD_LIBRARY_PATH` or
  `NEXUSQ_LIBRARY`.

## Usage

```java
import io.github.lecodev26.nexusq.Nexusq;

System.out.println("nexusq version: " + Nexusq.version());

Nexusq.Vault vault = Nexusq.Vault.create("my.nqv", "password", "my-label");
System.out.println("vault created at " + vault.path);
System.out.println("format version: " + vault.formatVersion);
```

Run with:

```bash
NEXUSQ_LIBRARY=/path/to/nexusq/target/debug/libnexusq.so java -cp ... your.Main
```

## What is available

- `Nexusq.version()` — returns the library version.
- `Nexusq.lastError()` — returns the last C SDK error message.
- `Nexusq.Vault`:
  - `Vault.create(path, password, label)` — creates a new vault (`label` may be null).
  - `vault.path` — returns the vault file path.
  - `vault.formatVersion` — returns the format version.
- `NexusqException` — the runtime exception raised on failures.

More operations land as the C SDK grows.

## Testing

Build and run the smoke test from the repository root:

```bash
mvn -f bindings/java -q package
NEXUSQ_LIBRARY=target/debug/libnexusq.so \
  java -cp bindings/java/target/classes:$(mvn -f bindings/java dependency:build-classpath -Dmdep.outputFile=/dev/stdout -q) \
  io.github.lecodev26.nexusq.examples.Smoke
```

The JUnit suite (`mvn -f bindings/java test`) covers the same contract:
version, vault round trip (with and without label) and error propagation.

The Java binding is intentionally a thin wrapper over the C SDK, matching
the Go SDK architecture. No cryptography or business logic is duplicated
in Java.

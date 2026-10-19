# NEXUS-Q Kotlin SDK

Kotlin bindings for NEXUS-Q. A thin wrapper over the
[C SDK](../../crates/nexusq-c) using [JNA](https://github.com/java-native-access/jna).
Published under the artifact coordinates `io.github.lecodev-26:nexusq-kotlin`.
Its API surface is independent of the Java binding (`io.github.lecodev-26:nexusq`).
It does not reimplement anything: every call goes through `libnexusq`.

## Requirements

- Kotlin 2.1 or newer (JVM), a JDK 11 or newer.
- The JNA jar on the classpath.
- The C SDK built (`cargo build -p nexusq-c`).
- `libnexusq.so` available at runtime through `LD_LIBRARY_PATH` or
  `NEXUSQ_LIBRARY`.

## Usage

```kotlin
import io.github.lecodev26.nexusq.kotlin.Nexusq

println("nexusq version: ${Nexusq.version()}")

val vault = Nexusq.Vault.create("my.nqv", "password", label = "my-label")
println("vault created at ${vault.path}")
println("format version: ${vault.formatVersion}")
```

`Vault.create` throws `IllegalStateException` with the library's last
error message when an operation fails.

## What is available

- `Nexusq.version()` — returns the library version.
- `Nexusq.lastError()` — returns the last C SDK error message.
- `Nexusq.Vault`:
  - `Vault.create(path, password, label = null)` — creates a new vault.
  - `vault.path` — returns the vault file path.
  - `vault.formatVersion` — returns the format version.

More operations land as the C SDK grows.

## Testing

Compile and run the smoke test from the repository root (JNA jar
downloaded by the Java module's Maven build):

```bash
JNA=$(find ~/.m2/repository/net/java/dev/jna -name 'jna-*.jar' | head -1)
kotlinc bindings/kotlin/src bindings/kotlin/examples -cp "$JNA" -include-runtime -d /tmp/nexusq-kotlin.jar
NEXUSQ_LIBRARY=target/debug/libnexusq.so \
  java -cp "/tmp/nexusq-kotlin.jar:$JNA" io.github.lecodev26.nexusq.kotlin.examples.SmokeKt
```

The Kotlin binding is intentionally a thin wrapper over the C SDK, matching
the Go SDK architecture. No cryptography or business logic is duplicated
in Kotlin.

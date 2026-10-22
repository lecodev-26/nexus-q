# NEXUS-Q .NET SDK

C# / .NET bindings for NEXUS-Q. A thin wrapper over the
[C SDK](../../crates/nexusq-c) using P/Invoke. It does not reimplement
anything: every call goes through `libnexusq`.

## Requirements

- .NET 9 SDK or newer (runtime: `net9.0`).
- The C SDK built (`cargo build -p nexusq-c`).
- `libnexusq.so` available at runtime through `LD_LIBRARY_PATH` or
  `NEXUSQ_LIBRARY`.

## Usage

```csharp
Console.WriteLine($"nexusq version: {Nexusq.Version()}");

var vault = Nexusq.Vault.Create("my.nqv", "password", "my-label");
Console.WriteLine($"vault created at {vault.Path}");
Console.WriteLine($"format version: {vault.FormatVersion}");
```

Run with:

```bash
NEXUSQ_LIBRARY=/path/to/nexusq/target/debug/libnexusq.so dotnet run --project your-app
```

## What is available

- `Nexusq.Version()` — returns the library version.
- `Nexusq.LastError()` — returns the last C SDK error message.
- `Vault`:
  - `Vault.Create(path, password, label)` — creates a new vault (`label` may be null).
  - `vault.Path` — returns the vault file path.
  - `vault.FormatVersion` — returns the format version.
- `NexusqException` — the exception thrown on failures.

More operations land as the C SDK grows.

## Testing

Run the smoke test from the repository root:

```bash
NEXUSQ_LIBRARY=target/debug/libnexusq.so dotnet run --project bindings/dotnet/examples/smoke
```

Expected output:

```
nexusq version: 4.1.1
vault created at /tmp/nexusq_dotnet_smoke_XXXXXX/vault.nqv
vault format version: 1
error propagation: ok
smoke test passed
```

The .NET binding is intentionally a thin wrapper over the C SDK, matching
the Go SDK architecture. No cryptography or business logic is duplicated
in C#.

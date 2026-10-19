# NEXUS-Q TypeScript SDK

TypeScript/Node.js bindings for NEXUS-Q. A thin wrapper over the
[C SDK](../../crates/nexusq-c) using the
[koffi](https://github.com/Neo-Fi/koffi) FFI package. It does not
reimplement anything: every call goes through `libnexusq`.

Node.js only; not for browsers.

## Requirements

- Node.js 18 or newer.
- The C SDK built (`cargo build -p nexusq-c`).
- `libnexusq.so` available at runtime through `LD_LIBRARY_PATH` or
  `NEXUSQ_LIBRARY`.

## Usage

```typescript
import { Vault, version } from "nexusq";

console.log(`nexusq version: ${version()}`);

const vault = Vault.create("my.nqv", "password", "my-label");
console.log(`vault created at ${vault.path}`);
console.log(`format version: ${vault.formatVersion}`);
```

Run with:

```bash
NEXUSQ_LIBRARY=/path/to/nexusq/target/debug/libnexusq.so node your_program.js
```

If the library directory is already on the dynamic loader path:

```bash
LD_LIBRARY_PATH=/path/to/nexusq/target/debug node your_program.js
```

## What is available

- `version()` — returns the library version.
- `lastError()` — returns the last C SDK error message.
- `Vault`:
  - `Vault.create(path, password, label?)` — creates a new vault.
  - `vault.path` — returns the vault file path.
  - `vault.formatVersion` — returns the format version.
- `NexusqError` — the error class raised on failures.

More operations land as the C SDK grows.

## Testing

Build and run the smoke test from the repository root:

```bash
cd bindings/typescript && npm install && npm run build && cd ../..
NEXUSQ_LIBRARY=target/debug/libnexusq.so npm --prefix bindings/typescript run smoke
```

Expected output:

```
nexusq version: 4.1.0
vault created at /tmp/nexusq_ts_smoke_XXXXXX/vault.nqv
vault format version: 1
error propagation: ok
smoke test passed
```

The TypeScript binding is intentionally a thin wrapper over the C SDK,
matching the Go SDK architecture. No cryptography or business logic is
duplicated in TypeScript.

# NEXUS-Q TypeScript SDK

TypeScript/Node.js bindings for NEXUS-Q. A thin wrapper over the
[C SDK](../../crates/nexusq-c) using the
[koffi](https://github.com/Neo-Fi/koffi) FFI package. It does not
reimplement anything: every call goes through `libnexusq`.

Node.js only; not for browsers.

## Installation and native runtime

- Node.js 18 or newer.
- On supported published releases, `npm install nexusq` downloads the matching
  prebuilt runtime and verifies its SHA-256 against the release checksum file.
  Rust and a local C SDK build are not required.
- Prebuilt targets: Linux x64/glibc, Linux ARM64/glibc, macOS ARM64, and Windows
  x64. Other OS/architecture/ABI combinations require a compatible library built
  separately.
- `NEXUSQ_LIBRARY` remains available as an advanced override. Runtime downloads
  are version-matched to the npm package and are never used to change the default
  provider: RustCrypto remains the default unless a native-enabled runtime is
  explicitly built and selected.

For a repository checkout where you are building the C library yourself, set
`NEXUSQ_SKIP_NATIVE_DOWNLOAD=1` during npm install and pass `NEXUSQ_LIBRARY` to
smoke tests.

## Usage

```typescript
import { Vault, version } from "nexusq";

console.log(`nexusq version: ${version()}`);

const vault = Vault.create("my.nqv", "password", "my-label");
console.log(`vault created at ${vault.path}`);
console.log(`format version: ${vault.formatVersion}`);
```

Most users can run the example directly after installing the package:

```bash
node your_program.js
```

For development or an advanced custom build, override the library path:

```bash
NEXUSQ_LIBRARY=/path/to/libnexusq.so node your_program.js
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
cd bindings/typescript && NEXUSQ_SKIP_NATIVE_DOWNLOAD=1 npm ci && npm run build && cd ../..
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

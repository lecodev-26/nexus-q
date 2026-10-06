# NEXUS-Q C SDK

> **Status:** Living reference document

The C SDK is the stable C ABI boundary for NEXUS-Q. It is implemented by
`crates/nexusq-c` and produces `libnexusq` plus the public header
`crates/nexusq-c/include/nexusq.h`.

## Architecture

The C layer is intentionally thin:

```text
NEXUS-Q Core (Rust)
        |
        v
   nexusq-c ABI
        |
        +--> C
```

No cryptography or independent security policy is implemented in the C
binding. It validates/marshals C arguments and delegates to `nexusq-core`.

## Building

```bash
cargo build -p nexusq-c
```

The dynamic library is written to `target/debug/libnexusq.so` and the static
library to `target/debug/libnexusq.a`.

The header is maintained/generated from the C binding API with cbindgen as
part of the SDK workflow.

## Current ABI

The current C ABI exposes:

- `nexusq_version()` — returns the library version.
- `nexusq_last_error_message()` — returns the last error on the calling
  thread.
- `nexusq_string_free()` — frees C strings allocated by the library.
- `nexusq_vault_create(path, password, label)` — creates a vault.
- `nexusq_vault_format_version(path)` — reads the vault format version.

Error-returning functions use a negative return code on failure and the
thread-local error accessor for diagnostics.

## C example

The repository smoke test is `examples/c/smoke.c`:

```bash
cargo build -p nexusq-c
cc \
  -I crates/nexusq-c/include \
  examples/c/smoke.c \
  -L target/debug -lnexusq \
  -o /tmp/nexusq-c-smoke
LD_LIBRARY_PATH=target/debug /tmp/nexusq-c-smoke
```

## ABI rules

- ABI functions use `extern "C"` and stable exported symbol names.
- Input pointers are validated at the boundary.
- The core owns cryptographic semantics; the C layer only translates types.
- Error messages are owned by the library and are valid until the next
  NEXUS-Q call on the same thread.
- ABI changes must be reviewed as compatibility-sensitive changes.

More operations will be added as the core public API and Phase 13 SDK surface
grow.

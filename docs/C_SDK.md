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

- `nexusq_version()` — returns a static, borrowed library-version string; do not free it.
- `nexusq_backend_name()` — returns a static, borrowed `rustcrypto` or `native-experimental` provider string; do not free it.
- `nexusq_backend_is_experimental()` — returns 1 for the experimental native provider, otherwise 0.
- `nexusq_last_error_message()` — returns a borrowed thread-local error string, valid only until the next NEXUS-Q call on the same thread; do not free it.
- `nexusq_string_free()` — deallocates only strings explicitly documented by an API as owned heap allocations. No current C ABI function returns such an allocation, so callers must not pass any current API return value to this function (null remains a no-op).
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
- Error messages are borrowed by callers, owned by the library, and valid only
  until the next NEXUS-Q call on the same thread. They must not be freed by callers.
- ABI changes must be reviewed as compatibility-sensitive changes.

More operations will be added as the core public API and Phase 13 SDK surface
grow.

## Sensitive data handling and zeroization

The C ABI does **not** implement cryptographic operations itself. All secret
material (passwords, key material, intermediate buffers) is owned and managed
by `nexusq-core`.

Callers **must**:

- Treat every password / key buffer passed into the ABI as sensitive.
- Zeroize their own copies of secrets as soon as they are no longer required
  (for example with explicit `memset_s` / `SecureZeroMemory` or equivalent).
- Never log, print, or persist the contents of `nexusq_last_error_message()`
  when the error may contain residual diagnostic data derived from secrets.

The library:

- Uses `Zeroizing` / `zeroize` features on the Rust side for key material and
  temporary buffers inside the core.
- Provides `nexusq_string_free()` for future APIs that explicitly return owned
  heap-allocated C strings. No current C ABI function returns such a string;
  static and thread-local borrowed strings must never be passed to the deallocator.
- Does not guarantee that the entire process address space is scrubbed; the
  C binding is a thin translation layer.

These contracts are part of the security boundary of the C SDK. Future ABI
additions that return or accept key material will document explicit ownership
and zeroization requirements.

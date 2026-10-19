# NEXUS-Q Python SDK

Python bindings for NEXUS-Q using PyO3. The binding is a thin native wrapper
over `nexusq-core`; it does not reimplement cryptography or business logic.

## Requirements

- Python 3.14 or newer for the current `abi3-py314` build target.
- Rust 1.85 or newer.
- `maturin` for building/installing the extension.

## Development build

From the repository root:

```bash
cd crates/nexusq-py
maturin develop
```

The resulting module is imported as `nexusq`.

## Current API

```python
import nexusq

print(nexusq.__version__)
print(nexusq.version())

vault = nexusq.Vault.create("my.nqv", "password", "my-label")
print(vault.path)
print(vault.format_version)
```

The current binding exposes:

- `nexusq.__version__`
- `nexusq.version()`
- `nexusq.Vault.create(path, password, label=None)`
- `Vault.path`
- `Vault.format_version`

## Architecture

Python calls `nexusq-core` directly through PyO3. This differs from the C-ABI
family (C, C++, Go and Ruby), which shares `libnexusq` as its ABI boundary.
The semantics are still defined by the same Rust core.

More operations will be exposed as the public Rust API grows.

## Sensitive data handling and zeroization

Passwords and any future key material passed through the Python binding are
treated as sensitive by the Rust core (`Zeroizing` / `zeroize` features).

Callers **must**:

- Avoid keeping passwords or key material in Python strings longer than
  necessary (Python strings are immutable and may be interned or remain in
  memory).
- Prefer short-lived local variables and avoid logging or serializing secrets.
- Be aware that CPython does not provide a portable secure-wipe for arbitrary
  Python objects; the binding therefore relies on the Rust core for zeroization
  of internal buffers.

The binding itself does not retain copies of passwords beyond the duration of
the call into `nexusq-core`. Future APIs that return key material will document
explicit ownership and clearing requirements.

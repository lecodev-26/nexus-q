# NEXUS-Q — Public API

> **Status:** Living reference document
> **Audience:** Contributors, integrators, SDK authors
> **Scope:** Public interfaces, layers, principles, versioning

---

## 1. Purpose

This document specifies **the public interfaces of NEXUS-Q**: what a
consumer of the library, CLI, or server can call, and under which
guarantees. It is the contract between NEXUS-Q and the code that uses it.

This document describes **shape and semantics**, not implementation.
Concrete signatures are implemented in the current `nexusq-core` API and
mirrored by the Phase 13 language bindings.

---

## 2. API layers

NEXUS-Q exposes four layers of API, from lowest to highest:

| Layer  | Target                | Language | Fase |
|--------|-----------------------|----------|------|
| L-A    | Rust library (`nexusq`) | Rust   | 2–6  |
| L-B    | CLI (`nexusq` binary) | CLI      | 12   |
| L-C    | Server (`nexusq-server`) | HTTP/IPC | 14 |
| L-D    | SDKs (Rust, C, C++, Python, Go, Ruby, CI-only TypeScript/Java/Kotlin/C#/Swift/Dart) | Multiple | 13/19 |

**Rule:** all layers are thin wrappers over L-A. No layer re-implements
logic that lives in the library. If a behavior exists in the CLI, it
exists in the library first.

---

## 3. API design principles

### 3.1 Strong types over bytes

Wherever possible, the API uses typed identifiers and structured records
(`KeyId`, `IdentityId`, `KeyRecord`, `Signature`) instead of ambiguous raw
values. Envelope payloads are currently represented as encoded `Vec<u8>`
inside the core API. This prevents argument-swapping
bugs and makes the API self-documenting.

### 3.2 Fail-closed, always

Every function that can fail returns a `Result`. There is no implicit
fallback, no silent default, no "best effort" in security-relevant
operations. If a caller does not handle the error, the operation did
not happen.

### 3.3 No secrets in return values

Functions never return private key material in plaintext. Keys are
returned as handles, KeyIds, or wrapped blobs. The only exception is
an explicit export API, which is documented separately and requires
explicit user confirmation.

### 3.4 Explicit over implicit

No global state, no ambient configuration, no hidden defaults for
security parameters. Every operation receives the session, the key,
the algorithm, and the data explicitly.

### 3.5 Non-leaking errors

Error messages do not distinguish between "wrong key" and "corrupt
ciphertext", or between "unknown user" and "wrong password". See
`SECURITY_MODEL.md` §6.3.

### 3.6 Zeroization on drop

Secret-bearing buffers returned by the core use zeroizing wrappers where
appropriate (for example, decrypted plaintext). Secret key material is
kept inside the vault/session boundary rather than exposed as a public
private-key type.

### 3.7 Thread safety

Public types are `Send + Sync` unless documented otherwise. Sessions
are `!Sync` (not shareable across threads without synchronization) but
may be `Send` (movable between threads).

### 3.8 No async in the core

The core library is synchronous. Async wrappers live in the SDK layer
(`nexusq-async`), built on top of the sync core. Rationale: async adds
complexity and runtime dependencies that we do not want in the
security-critical path.

---

## 4. Rust library API (L-A)

The Rust library is the primary interface. Everything else builds on it.

### 4.1 Current top-level surface

The current Rust API is centered on `Vault` and `Session` rather than a
separate `Nexus` façade:

```rust
let vault = Vault::create(path, password, label)?;
let session = vault.unlock(password)?;

let key_id = session.generate_key(Algorithm::Ed25519, Purpose::Sign)?;
let signature = session.identity_sign(&identity_id, message)?;

let envelope = session.encrypt(&key_id, plaintext, metadata)?;
let plaintext = session.decrypt(&envelope)?;

let vault = session.lock()?;
```

The exact signatures and error types are defined by `nexusq-core`; the
examples above are intentionally representative rather than a second API
specification.

### 4.2 Errors

The core exposes the unified `nexusq_core::Error` plus module-specific
errors (`VaultError`, `CryptoError`, `StorageError`, `HardwareError`,
`IdentityError`, and `PolicyError`). Bindings translate those failures into
the native error model of each language.

### 4.3 Lifecycle

The current lifecycle is:

```rust
let vault = Vault::create(path, password, label)?;
let session = vault.unlock(password)?;
// use session
let vault = session.lock()?;
```

`Vault::open(path)` is used to reopen an existing vault. There is no global
`Nexus` object and no asynchronous core API.

### 4.4 Key operations

The session exposes key creation, lookup, activation, rotation, revocation
and destruction, subject to algorithm-purpose validation and policy.

### 4.5 Data encryption

The current session API encrypts data into the NEXUS-Q envelope format and
returns the encoded envelope bytes. File helpers are available separately.

```rust
let envelope = session.encrypt(&key_id, data, metadata)?;
let plaintext = session.decrypt(&envelope)?;

let encrypted_path = session.encrypt_file(input_path, &key_id, metadata)?;
session.decrypt_file(&encrypted_path, output_path)?;
```

### 4.6 Signatures

Identity signatures are currently exposed through the identity API:

```rust
let identity_id = session.create_identity(Some("alice".into()))?;
let signature = session.identity_sign(&identity_id, message)?;
let valid = session.identity_verify(&identity_id, message, &signature)?;
```

### 4.7 Identity

```rust
let identity_id: IdentityId = session.create_identity()?;
session.identity_sign(&identity_id, &document)?;
session.identity_verify(&identity_id, &document, &signature)?;
```

### 4.8 What is NOT in the public API

· Direct access to key bytes (except through explicit export).
· Direct access to vault internals (metadata is exposed via accessors).
· Any function that operates on raw bytes without a type wrapper.
· Any function that bypasses the policy engine.

---

## 5. Error handling contract

### 5.1 Categories

· User errors: wrong password, malformed input, missing key. Return
  structured errors; the caller is expected to handle them.
· Environment errors: disk full, permission denied, hardware
  unavailable. Return structured errors; the caller may retry or
  report.
· Security errors: tamper detected, policy denied, attestation
  failed. Return structured errors; never retry automatically;
  never leak details to the end user beyond "operation denied".

### 5.2 No panics

The public API never panics on well-formed input. Panics indicate a bug
in NEXUS-Q, not a caller error. This is enforced by:

· #![deny(clippy::panic)] in the library crate.
· Fuzzing every public entry point (Fase 15).
· Documenting panics in the API docs if any exist (there should be none).

### 5.3 Error stability

Error variants are part of the API contract. Adding a variant is a minor
version bump; changing the meaning of an existing variant is a major
version bump.

---

## 6. CLI API (L-B)

The CLI (`nexusq`) is a thin wrapper over the library. It is designed for
humans and for scripting.

### 6.1 Command structure

```

nexusq <command> <subcommand> [options] [arguments]

```

### 6.2 Commands

The current CLI is:

**Vault:**
```
nexusq vault create <path> [--label <label>] [--password-file <path>]
nexusq vault status <path>
nexusq vault attach-audit <vault> <audit-dir> [--password-file <path>]
```

**Keys:**
```
nexusq key generate <vault> --algorithm <alg> --purpose <purpose>
nexusq key list <vault> [--password-file <path>]
nexusq key info <vault> <key-id> [--password-file <path>]
```

**Data:**
```
nexusq data encrypt <vault> --key-id <key-id> [--metadata <text>] <input>
nexusq data decrypt <vault> <input.nqx> <output>
```

**Signatures:**
```
nexusq sign sign <vault> --identity <identity-id> <input>
nexusq sign verify <vault> --identity <identity-id> <input> <signature>
```

**Identity:**
```
nexusq identity create <vault> [--label <label>]
nexusq identity list <vault>
```

**Credentials:**
```
nexusq credential issue <vault> --issuer <id> --subject <id> --claims <json> <output>
nexusq credential verify <vault> <input>
```

**Audit:**
```
nexusq audit verify <audit-dir> --vault <vault> [--password-file <path>] --vault <vault> [--password-file <path>]
nexusq audit show <audit-dir> [--last <n>]
```

**Diagnostics:**
```

nexusq health
nexusq diagnostics
nexusq version

```

### 6.3 Exit codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Generic error |
| 2    | Usage error (bad arguments) |
| 3    | Authentication failure |
| 4    | Authorization failure (policy denied) |
| 5    | Integrity failure (tamper detected) |
| 6    | Hardware failure |
| 7    | I/O failure |

### 6.4 Output formats

- **Human-readable** by default.
- `--output json` for machine-readable output.
- `--quiet` to suppress successful non-error output.
- **Never** intentionally print secrets to stdout/stderr.

### 6.5 Interactive prompts

For destructive operations (`key destroy`, `vault create`), the CLI
prompts for explicit confirmation. `--yes` bypasses prompts for
scripting, but **only** for operations explicitly marked as
script-safe.

`key destroy` requires typing the KeyId; `--yes` does not bypass this.

---

## 7. Server API (L-C)

The server (`nexusq-server`) exposes the library over HTTP. It is designed for:

- Multi-client deployments.
- Integration with applications that cannot link the library directly.
- Remote vault access (with appropriate network security).

### 7.1 Endpoints

The following routes are implemented by the current server:

```

POST   /v1/vault/unlock
POST   /v1/vault/lock
GET    /v1/vault/status

GET    /v1/keys
POST   /v1/keys
GET    /v1/keys/{key_id}
POST   /v1/keys/{key_id}/rotate
POST   /v1/keys/{key_id}/revoke
POST   /v1/keys/{key_id}/destroy

POST   /v1/encrypt
POST   /v1/decrypt
POST   /v1/sign
POST   /v1/verify

GET    /v1/audit
POST   /v1/audit/verify

GET    /v1/health
GET    /v1/ready
GET    /v1/version
GET    /metrics
GET    /readyz

```

### 7.2 Authentication

The server requires authentication for protected vault/crypto endpoints.
The liveness, readiness, version, and aggregate metrics endpoints are public:
`/health`, `/v1/health`, `/readyz`, `/v1/ready`, `/v1/version`, and `/metrics`.

The current implementation uses one configured bearer token. It is supplied as:

```text
Authorization: Bearer <server-token>
```

The token is loaded from `NEXUSQ_SERVER_TOKEN` and must be at least 32 bytes. It is compared in constant time. There is no login endpoint and the server does not currently issue short-lived tokens.

mTLS and signed-challenge authentication are architectural extension points, not implemented server transports in the current delivery boundary.

### 7.3 Authorization

Protected HTTP requests pass the current server authentication boundary. The core policy engine is available to vault/session operations, but caller identity and hardware-attestation context are not currently populated by the server. Do not describe the current HTTP layer as full identity-aware RBAC.

### 7.4 Transport

The current server speaks HTTP and does not terminate TLS itself. The safe default is loopback (`127.0.0.1`). Remote exposure requires a trusted TLS termination boundary and `NEXUSQ_TRUSTED_TLS_TERMINATION=1`.

Unix-socket transport is not part of the current server implementation.

### 7.5 Versioning

Endpoints are prefixed with `/v1/`. Adding endpoints is backward
compatible. Changing request/response schemas is a version bump.

### 7.6 Rate limiting

The server implements per-client rate limiting to prevent brute force
and DoS. Limits are configurable; defaults are conservative.

---

## 8. SDKs (L-D)

SDKs wrap the library for other languages and ecosystems.

### 8.1 Rust SDK

- Essentially the library itself, re-exported with a stable API surface.
- Async wrapper available in `nexusq-async`.

### 8.2 C SDK

- C ABI over the Rust library (via `cbindgen`).
- Header file `nexusq.h` with opaque handles.
- Designed for embedded, C++, and system-level integrators.
- Memory ownership documented per function.

### 8.3 Python SDK

- Built via PyO3 over `nexusq-core`.
- Current repository surface exposes version information and vault creation/metadata.
- Publication to PyPI is a release gate, not a completed publication claim.

### 8.4 Additional SDKs

C++, Go, Ruby and PHP bindings are present in the repository and use the C ABI family where applicable. TypeScript/Java/Kotlin/C#/Swift/Dart remain CI/release-scope work and are not presented as published SDKs.

### 8.5 SDK design rules

- **Same semantics** across languages. If Rust rejects an input, every
  SDK rejects it.
- **No re-implementation** of crypto. All SDKs call the Rust core.
- **Stable ABI** per major version.
- **Documented memory ownership** for C and any FFI.

---

## 9. API versioning and compatibility

### 9.1 Semantic versioning

NEXUS-Q follows SemVer for its APIs:

- **Major**: breaking changes to public API, formats, or semantics.
- **Minor**: backward-compatible additions.
- **Patch**: bug fixes, no API change.

### 9.2 What counts as a breaking change

- Removing or renaming a public function, type, or field.
- Changing the meaning of an existing error variant.
- Changing a persistent format in a way that requires migration.
- Changing a default parameter in a security-relevant way.

### 9.3 Deprecation policy

- Deprecated APIs remain functional for at least one minor version.
- Deprecation warnings are emitted at compile time (Rust) or runtime
  (other SDKs).
- Removal happens only in a major version bump.

### 9.4 Stability guarantees per layer

| Layer | Stability |
|-------|-----------|
| Rust library  | SemVer from v1.0 |
| CLI           | SemVer from v1.0; exit codes stable |
| Server API    | `/v1/` frozen at v1.0 |
| SDKs          | SemVer per SDK; documented per SDK |

Before v1.0, all layers are unstable and may change without notice.

---

## 10. Threat-model alignment

This document implements defenses for the following threats from
`THREAT_MODEL.md`:

- **T-04 (forged signatures)**: verify endpoint/function is explicit.
- **T-08 (key misuse)**: purpose enforcement in the API.
- **T-10 (silent downgrade)**: explicit algorithms, no fallback.
- **T-12 (cross-version format confusion)**: versioned API surface.

Out of scope for the API layer:

- **O-01 (compromised OS)**: the OS can intercept any API call.
- **O-08 (rubber-hose)**: not an API concern.

---

## 11. Open questions

- [ ] Exact Rust type signatures (Fase 2–6)
- [ ] IPC format: JSON, CBOR, custom binary
- [ ] Server framework: axum, hyper, other
- [ ] C SDK: how much of the API is exposed vs. Rust-only
- [ ] Python SDK: sync vs async default
- [ ] WASM: which features are available in browser (no filesystem?)

Resolved in Fase 12 (CLI), Fase 13 (SDK), Fase 14 (Server).

---

## 12. References

- `docs/ARCHITECTURE.md` — module structure
- `docs/KEY_MANAGEMENT.md` — key operation semantics
- `docs/SECURITY_MODEL.md` — errors, sessions, policy
- `docs/STORAGE.md` — persistent formats
- `docs/THREAT_MODEL.md` — threats and adversaries
- Semantic Versioning 2.0.0
- RFC 9110 — HTTP Semantics
- RFC 8446 — TLS 1.3

---

*End of document.*


### Trusted proxy configuration

When remote trusted TLS termination is enabled, also set `NEXUSQ_TRUSTED_PROXY_IPS` to the comma-separated IP addresses of the reverse proxies that may connect directly to NEXUS-Q. X-Forwarded-For is ignored for security decisions unless the peer socket is loopback or matches this allowlist; the address is selected by walking the chain from the right and skipping trusted proxy hops. This prevents direct clients from spoofing X-Forwarded-For to evade the rate limiter.

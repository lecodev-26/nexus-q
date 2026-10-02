# NEXUS-Q — Architecture

> **Status:** Draft (Fase 0)
> **Audience:** Contributors, reviewers, integrators
> **Scope:** System-level architecture, module boundaries, data flow

---

## 1. Purpose

This document describes how NEXUS-Q is structured internally: what
components exist, what each one is responsible for, and how they interact.

It is **not** a threat model (see `THREAT_MODEL.md`), nor a cryptography
specification (see `CRYPTOGRAPHY.md`). It is the blueprint that both of
those documents build upon.

---

## 2. Design principles

These principles drive every architectural decision in NEXUS-Q. Any change
that violates one of them requires an explicit justification and a note in
this document.

### 2.1 Do not invent cryptography

NEXUS-Q only uses standardized, peer-reviewed algorithms and maintained,
audited libraries. No custom ciphers, no homemade key schedules, no
"clever" variants.

If a primitive we need does not yet have a mature Rust implementation, we
wait, we integrate an audited C library, or we do not ship that primitive
in v1.0.

### 2.2 Library-first, binaries second

The core of NEXUS-Q is a **Rust library** (`libnexusq`). Everything else
is a consumer of that library:

- The CLI (`nexusq`) is a thin wrapper
- The server (`nexusq-server`) is another wrapper
- The SDKs (Rust, C, Python, TypeScript) bind to the library API
- The hardware backends plug in through traits

No business logic lives outside the library.

### 2.3 Hardware-agnostic

NEXUS-Q must run on:

- A laptop with no special hardware (software backend)
- A phone (Android / Termux, ARM, possibly TEE later)
- A server with TPM 2.0
- An embedded device with a Secure Element
- A RISC-V board with a custom root of trust

To make this possible, all hardware-dependent behavior is defined behind
traits. A "software backend" implements these traits with pure Rust;
hardware backends override them where available.

### 2.4 Fail closed, never leak partial results

If a cryptographic operation cannot complete (tampered input, missing key,
hardware error), the operation **fails**. It does not return partial
plaintext, it does not silently downgrade, it does not continue with
warning logs. The caller receives an error and no data.

### 2.5 Zeroization by default

Secret material (private keys, derived keys, plaintext buffers) is
zeroized in memory as soon as it is no longer needed, where the platform
permits it. This is best-effort: we document what we can and cannot
guarantee per platform.

### 2.6 Auditability

Every security-relevant operation (key creation, key use, vault unlock,
identity rotation, policy change) emits an audit event. Audit events never
contain secret material. They are append-only and tamper-evident.

### 2.7 Versioned formats on disk

Every persistent format NEXUS-Q writes (vault, envelope, storage DB) is
versioned from byte 0. Migration between versions is a first-class concern,
not an afterthought.

---

## 3. System overview

NEXUS-Q is organized in **four layers**. Each layer depends only on the
one immediately below it. Nothing skips layers.

```

┌─────────────────────────────────────────────────────────┐
│  L4 — Consumers                                          │
│  CLI  │  Server (HTTP/IPC)  │  SDKs (Rust/C/Py/TS)      │
└────────────────────────┬────────────────────────────────┘
│ public library API
┌────────────────────────▼────────────────────────────────┐
│  L3 — NEXUS-Q Core                                      │
│                                                         │
│   ┌────────┐  ┌────────┐  ┌──────────┐  ┌───────────┐  │
│   │ Crypto │  │ Vault  │  │ Identity │  │  Policy   │  │
│   └────┬───┘  └───┬────┘  └────┬─────┘  └─────┬─────┘  │
│        │          │            │              │        │
│   ┌────▼──────────▼────────────▼──────────────▼─────┐  │
│   │           Storage  │  Audit                    │  │
│   └───────────────────┬─────────────────────────────┘  │
└───────────────────────┼────────────────────────────────┘
│ trait interfaces
┌───────────────────────▼────────────────────────────────┐
│  L2 — Backends                                          │
│                                                         │
│   ┌─────────────────────┐   ┌─────────────────────────┐│
│   │  Software Backend   │   │  Hardware Backend       ││
│   │  - OS RNG           │   │  - TRNG / TPM / HSM     ││
│   │  - File storage     │   │  - Secure Element       ││
│   │  - In-memory vault  │   │  - RISC-V Keystore      ││
│   └─────────────────────┘   └─────────────────────────┘│
└───────────────────────┬────────────────────────────────┘
│ platform syscalls / drivers
┌───────────────────────▼────────────────────────────────┐
│  L1 — Platform                                          │
│  Linux  │  Android / Termux  │  macOS  │  Windows      │
│  ARM  │  x86_64  │  RISC-V                             │
└─────────────────────────────────────────────────────────┘

```

**Layer rules:**

- **L4** never calls L3 internals directly; only through the public API.
- **L3** never calls L1 directly; always through L2 traits.
- **L2** is the only layer that talks to the OS, filesystem, or devices.
- **L1** is whatever the OS/driver gives us. No NEXUS-Q code lives here.

---

## 4. Core modules (L3)

The NEXUS-Q Core is composed of six modules. Each one has a single
responsibility and a narrow public interface within the crate.

### 4.1 `crypto`

**Responsibility:** cryptographic primitives, and only primitives.

- Randomness abstraction (`RandomSource`)
- Hashing
- Key derivation (KDF)
- Key encapsulation (KEM, post-quantum)
- Digital signatures (post-quantum + classical)
- Symmetric AEAD encryption
- Key serialization / deserialization

**Does NOT:** manage key lifecycles, store keys, decide which key to use,
or talk to the OS.

**Depends on:** `error` only.

### 4.2 `vault`

**Responsibility:** secure storage of keys and secrets, with lifecycle.

- Key store (create, import, export public, rotate, revoke, destroy)
- Vault state machine (Locked / Unlocked / Sealed / Compromised)
- Access control (who can use this key, for what)
- Envelope encryption (protecting data with a random key, then wrapping
  that key under a long-term key)

**Does NOT:** implement primitives (delegates to `crypto`), or decide
policy (delegates to `policy`).

**Depends on:** `crypto`, `storage`, `policy`, `error`.

### 4.3 `identity`

**Responsibility:** digital identities and signatures.

- Identity objects (id, keys, metadata, status)
- Signing / verification of documents, messages, transactions, credentials
- Credential structures
- Key rotation for identities
- Revocation

**Depends on:** `crypto`, `vault`, `error`.

### 4.4 `policy`

**Responsibility:** the rules under which operations are allowed.

- Policy definition (key + operation + context)
- Evaluation (`allow`, `deny`, `require_*`)
- Context requirements: authentication, hardware, attestation
- Frequency / rate constraints

This is where NEXUS-Q stops being "just crypto" and becomes a **policy
enforcement layer**.

**Depends on:** `error`.

### 4.5 `storage`

**Responsibility:** persistent, versioned, encrypted storage.

- Vault database (metadata + wrapped keys)
- Atomic writes
- Crash recovery
- Backup / restore
- Version migration

**Does NOT:** decide what to store (that is `vault`'s job). It only knows
how to store bytes safely.

**Depends on:** `crypto` (for encryption of metadata), `error`.

### 4.6 `audit`

**Responsibility:** tamper-evident event log.

- Records security-relevant events (`KEY_CREATED`, `VAULT_UNLOCKED`, ...)
- Never records secrets
- Append-only
- Verifiable integrity

**Depends on:** `crypto` (for MAC/chaining), `storage`, `error`.

---

## 5. Public API surface (L3 → L4)

The core exposes a small, deliberate API. Everything else stays private.

Conceptual shape (final signatures in `API.md`):

```rust
// Vault lifecycle
Nexus::new(config) -> Result<Nexus, Error>
vault.create() -> Result<Vault, Error>
vault.unlock(credential) -> Result<Session, Error>
vault.lock(session) -> Result<(), Error>

// Keys
keys.generate(session, algorithm, purpose) -> Result<KeyId, Error>
keys.rotate(session, key_id) -> Result<KeyId, Error>
keys.revoke(session, key_id) -> Result<(), Error>
keys.destroy(session, key_id) -> Result<(), Error>

// Data protection
data.encrypt(session, key_id, plaintext) -> Result<Ciphertext, Error>
data.decrypt(session, key_id, ciphertext) -> Result<Plaintext, Error>

// Identity
identity.sign(session, identity_id, message) -> Result<Signature, Error>
identity.verify(identity_id, message, signature) -> Result<(), Error>
```

The concrete API will be refined during Fase 13 (SDK). This document
records the shape.

---

## 6. Backend traits (L2)

The boundary between L3 (core) and L2 (backends) is defined by **five
traits**. Every backend must implement all of them. The software backend
provides default implementations; hardware backends override specific
methods.

### 6.1 `RandomSource`

Provides cryptographic randomness.

```rust
pub trait RandomSource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), Error>;
    fn try_fill_bytes(&self, dest: &mut [u8]) -> Result<(), Error>;
}
```

· Software: OS RNG (getrandom, /dev/urandom, Android getrandom).
· Hardware: TRNG if available, with health checks.

### 6.2 SecureStorage

Provides persistent, tamper-resistant storage for wrapped keys and metadata.

```rust
pub trait SecureStorage {
    fn read(&self, key: StorageKey) -> Result<Vec<u8>, Error>;
    fn write(&self, key: StorageKey, data: &[u8]) -> Result<(), Error>;
    fn delete(&self, key: StorageKey) -> Result<(), Error>;
    fn list(&self, prefix: &str) -> Result<Vec<StorageKey>, Error>;
}
```

· Software: encrypted files on disk.
· Hardware: TPM NV storage, HSM slots, Secure Element files.

### 6.3 KeyProvider

Exposes hardware-protected key operations.

```rust
pub trait KeyProvider {
    fn generate(&self, spec: KeySpec) -> Result<Handle, Error>;
    fn sign(&self, handle: Handle, msg: &[u8]) -> Result<Signature, Error>;
    fn decrypt(&self, handle: Handle, ct: &[u8]) -> Result<Vec<u8>, Error>;
    fn destroy(&self, handle: Handle) -> Result<(), Error>;
}
```

· Software: in-memory keys (with zeroization).
· Hardware: keys never leave the secure boundary.

### 6.4 AttestationProvider

Allows the device to prove which software it is running.

```rust
pub trait AttestationProvider {
    fn measure(&self, component: &str) -> Result<Digest, Error>;
    fn attest(&self, nonce: &[u8]) -> Result<AttestationReport, Error>;
}
```

· Software: no-op or best-effort.
· Hardware: TPM quotes, Secure Element attestation, RISC-V measured boot.

### 6.5 SecureMemory

Optional trait for platforms that support locked / non-swappable memory.

```rust
pub trait SecureMemory {
    fn alloc(&self, size: usize) -> Result<SecureBuffer, Error>;
    fn lock(&self, buf: &SecureBuffer) -> Result<(), Error>;
    fn unlock(&self, buf: &SecureBuffer) -> Result<(), Error>;
}
```

· Software: best-effort (mlock where available, zeroization on drop).
· Hardware: enclave memory, on-chip SRAM.

---

## 7. Design decisions and rationale

### 7.1 Why library-first?

Because the same logic must be reused by the CLI, the server, and every
SDK. Duplicating security-critical code across binaries is how bugs are
born. There is exactly one implementation of every primitive, and
everything else calls it.

### 7.2 Why trait-based backends from day one?

Because retrofitting hardware abstraction later is painful. By defining
the five traits now, we:

· Force ourselves to write portable code from the start
· Make it easy to test with a fake backend (deterministic, no hardware)
· Enable hardware backends later without touching core logic

### 7.3 Why a separate policy module?

Because "can this key be used for this operation, right now, by this
caller?" is a distinct problem from "how do I sign?". Mixing them leads
to authorization logic scattered across the codebase. Keeping policy in
one place makes it auditable and testable.

### 7.4 Why is audit its own module instead of just logging?

Because logs are best-effort and can be lost, rotated, or tampered with.
Audit events in NEXUS-Q are security-relevant records: they are
chained (each event commits to the previous one), they never contain
secrets, and they can be verified independently.

### 7.5 Why version everything on disk?

Because we will change formats. A vault written by v1.0 must be readable
by v1.5 without data loss. This requires a version byte at the start of
every persistent structure, and a migration path documented per version.

---

## 8. What NEXUS-Q is NOT

To avoid scope creep, this document explicitly lists what NEXUS-Q is not
and will not become in v1.0:

· Not a password manager. It manages cryptographic keys, not user
  passwords (though it can be used as a backend by one).
· Not a VPN, firewall, or network security tool.
· Not an authentication server. It provides identities and signatures;
  integrating them into a login flow is the integrator's job.
· Not a blockchain, ledger, or distributed system in v1.0. Distributed
  vaults are a v1.2+ concern.
· Not a certificate authority. It issues signatures, not X.509 certs.
· Not a replacement for hardware security. It uses hardware when
  available; it does not turn a general-purpose CPU into an HSM.

If a feature request does not fit one of the six core modules, it likely
belongs in a downstream project, not in NEXUS-Q.

---

## 9. Open questions

Items deferred to later phases; each will be resolved in its own document.

☐ Concrete PQC algorithms to ship in v1.0 (see CRYPTOGRAPHY.md)
☐ Envelope format details (see STORAGE.md)
☐ Policy language: Rust structs vs. a small DSL (see API.md)
☐ Hardware attestation: which platforms in v1.0 (see THREAT_MODEL.md)
☐ Distributed vault: architecture (v1.2+, not in scope for this doc)

---

## 10. References

· docs/THREAT_MODEL.md — what we protect against
· docs/CRYPTOGRAPHY.md — algorithms and rules
· docs/KEY_MANAGEMENT.md — key lifecycle
· docs/SECURITY_MODEL.md — security guarantees and assumptions
· docs/STORAGE.md — persistent formats and migration
· docs/API.md — public interfaces
· docs/ROADMAP.md — phased development plan

---

End of document.

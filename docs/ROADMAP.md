# AXIOM NEXUS-Q — Roadmap

> **Status:** Living document (Fase 0)
> **Audience:** Contributors, users, stakeholders
> **Scope:** Phased development plan from bootstrap to v1.0 and beyond

---

## 1. End goal

> **AXIOM NEXUS-Q** is a post-quantum cryptographic security engine for
> protecting data, keys, and identities. It is usable by applications,
> servers, and devices — from a laptop with no special hardware to an
> embedded device with a Secure Element.

The final architecture supports:

- **Applications** (web, server, mobile) via SDK / API / CLI
- **NEXUS-Q Core** with six modules: Crypto, Vault, Identity, Policy,
  Storage, Audit
- **Two backends**: Software and Hardware
- **Hardware integrations**: TRNG, HSM, TPM, Secure Element, RISC-V,
  Enclave

---

## 2. How we work

### 2.1 Discipline

No phase is skipped. Each phase has:

- **Objective** — what we are trying to achieve.
- **Deliverables** — concrete artifacts (code, docs, tests).
- **Exit criteria** — what must be true to consider the phase done.

A phase is done when its exit criteria are met, not when we get bored.

### 2.2 Workflow

```

ROADMAP
↓
EPIC
↓
MILESTONE
↓
ISSUE
↓
BRANCH
↓
CODE
↓
TEST
↓
PULL REQUEST
↓
MERGE

```

### 2.3 Issue naming

Issues are tracked as `NQ-NNN` for epics, `NQ-NNN-MM` for sub-issues.

Example:

```

NQ-002  Crypto Core
├── NQ-002-01  Random
├── NQ-002-02  Hash
├── NQ-002-03  KDF
├── NQ-002-04  KEM
├── NQ-002-05  Signatures
├── NQ-002-06  AEAD
└── NQ-002-07  Tests

```

### 2.4 Commits

Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`,
`refactor:`, `perf:`, `build:`, `ci:`).

Each commit is atomic: one logical change. Reverts are cheap.

### 2.5 Branches

- `main` is always green (compiles, tests pass, no fuzz crashes).
- Feature branches: `feat/<short-desc>`, `fix/<short-desc>`,
  `docs/<short-desc>`.
- Branches are short-lived; merge via PR.

---

## 3. Phase 0 — Foundations

**Objective:** Define what NEXUS-Q is before writing code.

**Deliverables:**

- [x] Repository bootstrapped with `.gitignore`, licenses, README
- [x] `docs/ARCHITECTURE.md`
- [x] `docs/THREAT_MODEL.md`
- [x] `docs/CRYPTOGRAPHY.md`
- [x] `docs/KEY_MANAGEMENT.md`
- [x] `docs/SECURITY_MODEL.md`
- [x] `docs/STORAGE.md`
- [x] `docs/API.md`
- [x] `docs/ROADMAP.md` (this document)

**Exit criteria:**

- All eight documents reviewed and committed.
- No open question blocks Fase 1.

**Status:** ✅ Complete.

---

## 4. Phase 1 — Project restructuring

**Objective:** Convert the placeholder skeleton into a real Rust
workspace.

**Deliverables:**

- `Cargo.toml` workspace configuration
- Library crate (`nexusq`) with module structure:
  - `src/lib.rs`
  - `src/error.rs`
  - `src/crypto/`
  - `src/vault/`
  - `src/identity/`
  - `src/hardware/`
  - `src/storage/`
  - `src/policy/`
- Error hierarchy (`CryptoError`, `VaultError`, ...)
- Fundamental types (`KeyId`, `Algorithm`, `Ciphertext`, ...)
- CI: build, clippy, fmt, test on push

**Exit criteria:**

- `cargo build` compiles clean on Linux, macOS, Termux.
- `cargo clippy -- -D warnings` passes.
- `cargo fmt --check` passes.
- All modules exist with at least placeholder types.

---

## 5. Phase 2 — Crypto Core

**Objective:** Implement the cryptographic primitives specified in
`CRYPTOGRAPHY.md`.

**Deliverables:**

- `RandomSource` trait + software implementation
- Hash wrappers (SHA-256, SHA-512, SHA3)
- KDF wrappers (Argon2id, HKDF)
- AEAD wrappers (AES-256-GCM, ChaCha20-Poly1305)
- KEM wrappers (ML-KEM-768, ML-KEM-1024, hybrid with X25519)
- Signature wrappers (ML-DSA-65, ML-DSA-87, SLH-DSA, Ed25519 legacy)
- Key serialization / deserialization
- Zeroization on drop for all secret types
- Unit tests per primitive
- Known-Answer Tests (KAT) when available

**Exit criteria:**

- All primitives implemented and tested.
- KATs pass for every algorithm.
- Negative tests (wrong key, corrupted ciphertext, malformed input)
  pass.
- No panics on untrusted input.

---

## 6. Phase 3 — Key management

**Objective:** Implement the key lifecycle specified in
`KEY_MANAGEMENT.md`.

**Deliverables:**

- [x] `KeyId` generation and parsing
- [x] Key metadata structures (all fields)
- [x] Key lifecycle state machine
- [x] Key purpose enforcement
- [ ] Rotation, revocation, destruction operations (moved to Phase 4)
- [ ] Audit event emission for every operation (moved to Phase 4)

**Exit criteria:**

- [x] State machine transitions tested exhaustively.
- [x] Forbidden transitions rejected.
- [ ] Rotation and revocation have end-to-end tests (Phase 4).
- [ ] Audit events verified for every operation (Phase 4).

**Status:** ✅ Structural part complete. Operational part (rotation,
revocation, destruction as actual vault operations) is implemented in
Phase 4 where it can be tied to persistence and audit.

---

## 7. Phase 4 — NEXUS Vault

**Objective:** Implement the vault module: secure container for keys
and metadata.

**Deliverables:**

- [x] Vault file format (F-01, see `STORAGE.md` §4)
- [x] Vault state machine (LOCKED, UNLOCKED, SEALED, COMPROMISED)
- [x] Session management (create, use, terminate)
- [x] Key store operations: create, list, find, activate, rotate,
      revoke, destroy
- [ ] Access control (via policy engine, at least minimal) — deferred
      to Phase 11 (Policy Engine), which is where it belongs
- [ ] Audit log integration — deferred to Phase 5+, since the audit
      module is not yet implemented
- [x] Envelope encryption primitives (material wrapping), used here
      for key storage

**Exit criteria:**

- [x] Vault can be created, unlocked, used, locked, reopened.
- [x] Tampered vault files are detected and refused.
- [x] Wrong passwords are detected without full decryption.
- [x] Atomic write verified: temp file, fsync, rename, directory
      fsync. Concurrent writers use unique temp names.

**Status:** ✅ Complete, except for access control (Phase 11) and
audit log integration (Phase 5+). Those are tracked separately and do
not block moving to Phase 5.

---

## 8. Phase 5 — Envelope encryption

**Objective:** Implement the envelope format (F-02), so NEXUS-Q can
protect real data.

**Deliverables:**

- [x] Envelope format `NQX1` (see `STORAGE.md` §5 and ADR 0003)
- [x] Encrypt / decrypt operations (in memory)
- [x] Envelope to vault key (vault mode)
- [x] Envelope to public key (public-key mode, ML-KEM-768 hybrid)
- [x] AAD binding (whole header is AAD for the payload)
- [x] Corruption detection (no partial plaintext)
- [x] File operations with `.nqx` extension
- [ ] CLI commands for encrypt / decrypt — deferred to Phase 12 (CLI)

**Exit criteria:**

- [x] Round-trip encryption/decryption works for various payloads.
- [x] Tampered envelopes fail with no partial plaintext.
- [x] Envelopes to public keys can be decrypted by the recipient.
- [x] Metadata is authenticated.

**Status:** ✅ Complete, except for CLI integration (Phase 12).

---

## 9. Phase 6 — Identity

**Objective:** Implement digital identities with signing, rotation, and
revocation.

**Deliverables:**

- Identity object (`IdentityId`, keys, metadata, status)
- Separate identity keys: signing, encryption, key agreement
- Credential structures
- Identity signing (documents, transactions, credentials, messages)
- Identity verification (by third parties)
- Identity rotation (keys change, identity persists)
- Identity revocation

**Exit criteria:**

- Identities can be created, used to sign, and verified.
- Rotation preserves the identity while changing keys.
- Revocation is honored by verifiers.
- Credential structures documented and tested.

---

## 10. Phase 7 — Hardware abstraction

**Objective:** Define and implement the backend traits so NEXUS-Q runs
on multiple platforms.

**Deliverables:**

- `RandomProvider` trait (see `ARCHITECTURE.md` §6.1)
- `SecureStorage` trait (§6.2)
- `KeyProvider` trait (§6.3)
- `AttestationProvider` trait (§6.4)
- `SecureMemory` trait (§6.5)
- Software backend implementation
- Stubs for hardware backends (TPM, HSM, Secure Element, RISC-V)

**Exit criteria:**

- All traits defined and documented.
- Software backend implements all traits.
- Core library works against the software backend without changes.
- Hardware backend stubs compile and pass "not implemented" tests.

---

## 11. Phase 8 — TRNG

**Objective:** Use hardware randomness when available, with health
checks.

**Deliverables:**

- Hardware RNG detection (platform-dependent)
- Health checks (entropy estimation, statistical tests)
- Fallback policy (documented in threat model)
- Integration with `RandomSource`

**Exit criteria:**

- On platforms with a hardware RNG, it is used.
- Health check failures are detected and trigger fallback.
- Policy for fallback is documented and tested.

---

## 12. Phase 9 — RISC-V / Secure environment

**Objective:** Support secure boot, measured boot, and hardware keys on
RISC-V and enclave platforms.

**Deliverables:**

- Secure boot integration (boot ROM → verified bootloader → verified
  NEXUS-Q)
- Measured boot (measure components before execution)
- Hardware keys that never leave the secure environment
- Secure memory usage (reduce secret exposure)
- Device attestation ("I am running this exact trusted software")
- Crypto acceleration (when hardware supports it)

**Exit criteria:**

- On a supported platform, boot chain is verified end-to-end.
- Attestation reports are generated and verified.
- Hardware keys are used for high-value operations.
- No plaintext key material leaves the secure environment.

---

## 13. Phase 10 — Storage

**Objective:** Implement the full storage layer per `STORAGE.md`.

**Deliverables:**

- Storage DB (F-03)
- Audit log (F-04) with segmentation and chaining
- Backup bundle (F-05)
- Atomic writes across all formats
- Crash recovery
- Version migration machinery
- Reserved extensions enforced

**Exit criteria:**

- All five formats (F-01 through F-05) work end-to-end.
- Crash recovery tested (simulated power loss).
- Migration from v1 format to v2 format (artificial) works.
- Corrupt files are detected and refused.

---

## 14. Phase 11 — Policy engine

**Objective:** Enforce security policies on every operation.

**Deliverables:**

- Policy definition (Rust structs, or small DSL)
- Policy evaluation: `allow`, `deny`, `require_authentication`,
  `require_hardware`, `require_attestation`
- Frequency / rate constraints
- Policy changes are audited
- Default-deny enforced

**Exit criteria:**

- Policies can be defined, loaded, and applied.
- Deny-by-default verified.
- All key operations respect policy.
- Policy violations produce audit events.

---

## 15. Phase 12 — CLI

**Objective:** Provide a human-usable command-line interface.

**Deliverables:**

- `nexusq` binary with all commands from `API.md` §6.2
- Exit codes (0-7) implemented
- Output formats: human, `--json`, `--quiet`
- Interactive prompts for destructive operations
- Never print secrets

**Exit criteria:**

- All commands work end-to-end.
- Exit codes are correct per operation.
- `--json` output is stable and documented.
- Scripts can use the CLI safely (no interactive surprises).

---

## 16. Phase 13 — SDK / API

**Objective:** Expose the library in multiple languages.

**Deliverables:**

- Rust SDK (stable public API)
- C SDK (`cbindgen` header)
- Python SDK (PyO3, published to PyPI)
- TypeScript SDK (WASM, for Node.js and browsers)

**Exit criteria:**

- Each SDK provides the same semantics as the Rust library.
- Cross-SDK tests confirm consistent behavior.
- Documentation per SDK.
- Published packages (crates.io, PyPI, npm).

---

## 17. Phase 14 — Server mode

**Objective:** Run NEXUS-Q as a service.

**Deliverables:**

- `nexusq-server` binary
- HTTP API (`/v1/` endpoints per `API.md` §7)
- Authentication (bearer, mTLS, signed challenges)
- Authorization via policy engine
- Rate limiting
- HTTPS-only for remote, Unix socket for local
- Audit log integration

**Exit criteria:**

- Server handles concurrent clients safely.
- Authentication and authorization enforced.
- Rate limiting prevents brute force.
- Server can be deployed in containers.

---

## 18. Phase 15 — Security engineering

**Objective:** Make NEXUS-Q secure in practice, not just in design.

**Deliverables:**

- Unit tests, integration tests, property tests, fuzz tests, negative
  tests, interoperability tests
- Fuzzing harnesses for: parsers, serialization, envelope, network API,
  storage, key import/export
- Dependency security: `cargo audit`, `cargo deny`, SBOM
- Supply chain protections: GitHub Actions, CI/CD, signed releases
- Reproducible builds (aspirational)
- Secret scanning in the repo

**Exit criteria:**

- Fuzzing runs for 24+ hours without crashes.
- `cargo audit` reports no known vulnerabilities.
- SBOM generated per release.
- Reproducible build demonstrated on at least one platform.

---

## 19. Phase 16 — Side-channel and hardening

**Objective:** Reduce exposure to timing, memory, and cache side
channels.

**Deliverables:**

- Documented constant-time guarantees per primitive
- No secret-dependent branches in our code
- No secret-dependent memory access patterns
- Key lifetime in memory minimized
- Zeroization verified where the platform supports it
- Documented per-platform limitations

**Exit criteria:**

- Every primitive has a documented constant-time claim.
- Static analysis (`clippy`, `cargo-deny`, custom lints) enforces
  no-branch-on-secret rules where possible.
- Zeroization tests pass (memory overwritten).

---

## 20. Phase 17 — Benchmarking

**Objective:** Measure performance honestly.

**Deliverables:**

- Benchmarks for: key generation, KEM encapsulate/decapsulate,
  sign/verify, encrypt/decrypt, vault operations, key rotation, storage,
  API latency
- Results on: desktop, server, ARM, RISC-V, embedded
- Public benchmark report per release

**Exit criteria:**

- Benchmarks reproducible on at least 3 platforms.
- Numbers published in `BENCHMARKS.md`.
- No performance claims without measurement.

---

## 21. Phase 18 — Observability

**Objective:** Make NEXUS-Q operable in production.

**Deliverables:**

- Metrics: operations/sec, latency, errors, key usage, vault
  operations, hardware status
- Logging (no secrets)
- Health endpoint (`nexusq health`)
- Diagnostics command (`nexusq diagnostics`)

**Exit criteria:**

- Metrics exposed in a standard format (Prometheus or equivalent).
- Logs are structured and safe (no secrets).
- Health and diagnostics work end-to-end.

---

## 22. Phase 19 — Deployment

**Objective:** Ship NEXUS-Q to real users on real platforms.

**Deliverables:**

- Packages: `.deb`, `.rpm`, `.tar.gz`, containers (Docker / OCI)
- Platforms: Linux (x86_64, aarch64), Termux (aarch64), macOS, Windows
- CI/CD: build → test → fuzz → security → benchmark → release
- Signed releases with checksums

**Exit criteria:**

- Package installs cleanly on supported platforms.
- Container runs with documented entrypoint.
- CI/CD automates the release process.
- Releases are signed and verifiable.

---

## 23. Phase 20 — User documentation

**Objective:** Another person can install and use NEXUS-Q without us.

**Deliverables:**

- `docs/user/`:
  - Getting Started
  - Installation
  - CLI Guide
  - API Guide
  - Vault Guide
  - Identity Guide
  - Crypto Guide
  - Hardware Guide
  - Security Guide
  - Deployment Guide
  - Troubleshooting
- `examples/`: encrypt file, sign document, server, identity, hardware

**Exit criteria:**

- A new user can complete a first workflow following only the docs.
- All examples run without modification on supported platforms.

---

## 24. Phase 21 — Audit

**Objective:** Independent review before v1.0.

**Deliverables:**

- External crypto review
- Memory safety review
- Threat model review
- API review
- Key management review
- Storage review
- Hardware integration review
- Dependency review
- Fuzzing results published
- Penetration testing report
- Documented known limitations, risks, accepted risks, future work

**Exit criteria:**

- All findings triaged and addressed or explicitly accepted.
- Audit reports published (or summarized) in the repository.
- No open critical or high-severity issues.

---

## 25. Phase 22 — NEXUS-Q v1.0

**Objective:** Release the first stable version.

**Definition of v1.0:** all of the following must be true:

- ✓ PQC crypto (ML-KEM, ML-DSA, SLH-DSA) implemented and tested
- ✓ Key management (lifecycle, rotation, revocation, destruction)
- ✓ Secure vault (format F-01, atomic writes, crash-safe)
- ✓ Envelope encryption (format F-02)
- ✓ Digital signatures (identity, credentials)
- ✓ Identity system (create, sign, verify, rotate, revoke)
- ✓ Policy engine (deny by default)
- ✓ Secure storage (all five formats)
- ✓ CLI (all commands, exit codes)
- ✓ Rust SDK (stable public API)
- ✓ Server / API (HTTP `/v1/`)
- ✓ Hardware abstraction (traits + software backend)
- ✓ TRNG support (with health checks)
- ✓ Extensive testing (unit, integration, property, negative)
- ✓ Fuzzing (24h+ no crashes)
- ✓ Security hardening (side channels documented)
- ✓ Documentation (user + developer)
- ✓ Benchmarks (published)
- ✓ Reproducible releases (signed, checksummed)
- ✓ Independent audit completed

**Exit criteria:**

- All checkboxes above are checked.
- v1.0.0 tag created and signed.
- Release notes published.

---

## 26. After v1.0

### v1.1 — Ecosystem expansion

- Python SDK
- TypeScript SDK
- C SDK
- Better hardware support (TPM 2.0 mature, first HSM integration)
- Remote vault (access vault over network)
- Improved audit system

### v1.2 — Distribution and enterprise

- Distributed vault (multi-node architecture)
- Enterprise policy engine (richer rules, RBAC)
- HSM integrations (PKCS#11, vendor-specific)
- Cloud integrations (AWS KMS, GCP KMS, Azure Key Vault as backends)

### v2.0 — Platform

AXIOM NEXUS-Q becomes the cryptographic core of a broader platform:

```

AXIOM NEXUS
│
┌────────────┼────────────┐
▼            ▼            ▼
NEXUS-Q       Identity      Hardware
Crypto        Platform       Security
│            │            │
└────────────┼────────────┘
▼
AXIOM SECURITY
PLATFORM

```

At that point, NEXUS-Q is no longer just a project on GitHub — it is
infrastructure.

---

## 27. Phase summary

| Phase | Name                          | Status |
|-------|-------------------------------|--------|
| 0     | Architecture and foundations  | ✅ Done |
| 1     | Project restructuring         | ⏳ Next |
| 2     | Crypto Core                   | Pending |
| 3     | Key Management                | Pending |
| 4     | NEXUS Vault                   | Pending |
| 5     | Envelope Encryption           | Pending |
| 6     | Identity                      | Pending |
| 7     | Hardware Abstraction          | Pending |
| 8     | TRNG                          | Pending |
| 9     | RISC-V / Secure Environment   | Pending |
| 10    | Storage                       | Pending |
| 11    | Policy Engine                 | Pending |
| 12    | CLI                           | Pending |
| 13    | SDK / API                     | Pending |
| 14    | Server Mode                   | Pending |
| 15    | Security Engineering          | Pending |
| 16    | Side Channel / Hardening      | Pending |
| 17    | Benchmarking                  | Pending |
| 18    | Observability                 | Pending |
| 19    | Deployment                    | Pending |
| 20    | User Documentation            | Pending |
| 21    | Audit                         | Pending |
| 22    | v1.0                          | Pending |

---

## 28. Priorities and non-goals

**Priorities for v1.0:**

1. Correctness and security over features.
2. Post-quantum by default.
3. Portability across platforms (Linux, Termux, macOS, Windows).
4. Documentation that another person can follow.
5. Honest measurement (benchmarks, audits).

**Explicit non-goals for v1.0:**

- Distributed vault (v1.2+).
- Multi-party computation (future).
- Key escrow (never).
- Blockchain integration.
- GUI application (CLI + API only).
- Mobile native apps (SDKs only).

---

## 29. References

- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/CRYPTOGRAPHY.md`
- `docs/KEY_MANAGEMENT.md`
- `docs/SECURITY_MODEL.md`
- `docs/STORAGE.md`
- `docs/API.md`

---

*End of document.*

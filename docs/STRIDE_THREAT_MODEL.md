# NEXUS-Q STRIDE Threat Assessment

> **Status:** Living security assessment; implementation-linked, not an independent audit
> **Reviewed:** 2026-11-14
> **Architecture baseline:** `main` at `fc14fb26a32864d3f18bc3946876f8a624c35eb2`
> **Audience:** Maintainers, security reviewers, integrators, auditors
> **Method:** STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege)

## 1. Purpose and review method

This assessment turns the adversaries, assets, trust boundaries, and attack surfaces in [`THREAT_MODEL.md`](THREAT_MODEL.md) into concrete abuse cases. Each case is mapped to implemented controls, repository evidence, and residual risk. It is intended to be updated with architecture and security-relevant code changes.

The review was performed against the repository architecture and implementation documentation, including `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`, `docs/THREAT_MODEL.md`, `docs/POLICY.md`, `docs/KEY_MANAGEMENT.md`, `docs/STORAGE.md`, the Rust core, HTTP server, C ABI, fuzz targets, tests, and GitHub Actions workflows. File and test references below identify evidence to inspect; they are not claims that a new test was run as part of this documentation change.

**Assessment limits:** this is a repository-level design review, not a penetration test, formal verification, cryptographic implementation audit, deployment assessment, or certification. A control is not considered proven solely because it is described in documentation.

## 2. System context and components

NEXUS-Q is library-first. The Rust core owns cryptographic operations, vault/key lifecycle, identity, policy evaluation, and persistent storage. Consumers include the CLI, HTTP server, C ABI and language bindings/SDKs. Hardware and software providers are reached through backend interfaces; the backend ultimately relies on operating-system facilities, filesystems, drivers, and devices.

Relevant implementation locations:

| Component | Responsibility / relevant paths |
|---|---|
| Core cryptography | `crates/nexusq-core/src/crypto/` — AEAD, KDF, KEM, signatures, hashing, randomness |
| Vault and key lifecycle | `crates/nexusq-core/src/vault/` — vault state, key records, envelopes, lifecycle, file operations |
| Identity and credentials | `crates/nexusq-core/src/identity/` |
| Authorization | `crates/nexusq-core/src/policy/` |
| Storage and audit | `crates/nexusq-core/src/storage/` — atomic writes, backups, audit events/logs/segments |
| HTTP service | `crates/nexusq-server/src/main.rs` — bearer authentication, request limits, rate limiting, session timeout, endpoints |
| CLI | `crates/nexusq-cli/src/` |
| C ABI | `crates/nexusq-c/src/lib.rs` and `docs/C_SDK.md` |
| Hardware interfaces/providers | `crates/nexusq-core/src/hardware/` and `crates/nexusq-native-backend/` |
| Dependency/build pipeline | `.github/workflows/`, `Cargo.toml`, `Cargo.lock`, `.cargo/`, `supply-chain/` |

The root Cargo workspace inventory and separately managed native/Arena workspaces have different CI and dependency-audit boundaries. The cargo-geiger inventory introduced for the root workspace must not be read as coverage of every separately locked workspace.

## 3. Actors

| Actor | Trust / capabilities | Main objectives |
|---|---|---|
| Vault owner / administrator | Authorized operator with access to vault credentials and server configuration | Create, unlock, manage, back up, and recover keys and data |
| Application / SDK consumer | Calls public Rust, C, Python, TypeScript, or HTTP-facing integration surfaces as applicable | Use cryptographic and key-management capabilities; may supply malformed or hostile inputs |
| Remote API client | Network peer; trusted only after server bearer-token authentication | Invoke exposed operations; may be malicious or compromised |
| Local unprivileged process | Runs on the same host under another account or process identity | Read accessible files, probe IPC/network surfaces, exhaust resources, or exploit platform boundaries |
| Malware in the user's security context | Executes with the user's privileges and may observe input or process state | Steal credentials, plaintext, tokens, or active-session material |
| Privileged host / hypervisor attacker | Controls kernel, process memory, drivers, or virtualized host | Bypass software isolation and extract or alter secrets |
| Supply-chain / build actor | Controls or compromises a dependency, toolchain, CI runner, repository credential, or release account | Introduce malicious code or substitute release artifacts |
| Hardware / firmware provider | Supplies TPM, HSM, Secure Element, RNG, or native implementation | May fail, be misconfigured, or be malicious; trust is provider- and deployment-dependent |

## 4. Assets and security objectives

The asset identifiers retain the mapping in `THREAT_MODEL.md` and extend it to integration and delivery assets.

| ID | Asset | Priority | Required security properties |
|---|---|---|---|
| A1 | Long-term private keys and identity signing/KEM keys | Critical | Confidentiality, integrity, controlled use, lifecycle accountability |
| A2 | Data-encryption keys and wrapped key material | Critical | Confidentiality, integrity, purpose binding, safe destruction/rotation |
| A3 | User plaintext and decrypted payloads | High | Confidentiality, integrity, bounded exposure in memory and outputs |
| A4 | Identity records, public keys, credentials, revocation state | High | Authenticity, integrity, correct verification and status handling |
| A5 | Vault metadata, policies, key identifiers, configuration | Medium–High | Integrity, access control, limited disclosure |
| A6 | Audit events, segment chain, encrypted vault audit anchor | High | Integrity, ordering, rollback/truncation detection, accountable retention |
| A7 | Service availability and correctness of security decisions | High | Resource bounds, fail-closed behavior, predictable errors |
| A8 | Server bearer token, user credentials, recovery material | Critical | Confidentiality, rotation, restricted access, non-disclosure in logs |
| A9 | Source, dependencies, build outputs, SDK runtime artifacts | High | Provenance, integrity, reviewability, reproducible identification |
| A10 | Backend/provider identity and configuration | High | Correct provider selection, explicit experimental status, no silent substitution |

## 5. Trust boundaries

| Boundary | Data/control crossing it | Required treatment |
|---|---|---|
| TB1 — Consumer to public Rust API | Caller-provided bytes, identifiers, options, credentials, serialized objects | Treat inputs as hostile; validate lengths, formats, states, and operation preconditions |
| TB1a — Foreign-language caller to C ABI | Raw pointers, NUL-terminated strings, ownership and lifetime assumptions | Enforce documented ABI preconditions; validate null/UTF-8 where possible; callers remain responsible for valid readable pointers and correct ownership |
| TB1b — Network client to HTTP server | HTTP headers, bearer token, JSON bodies, forwarded-proxy metadata | Authenticate protected routes, bound body size and request rate, require trusted TLS termination for non-loopback exposure |
| TB2 — Core to backend traits | Randomness, storage, key-provider and hardware operations/results | Treat provider failures as errors; do not silently downgrade; hardware trust depends on provider and attestation evidence |
| TB3 — Backend to platform | OS RNG, filesystem, syscalls, drivers, devices | Platform is outside the core trust boundary; document OS, filesystem, and device assumptions |
| TB4 — Build/release boundary | Dependencies, toolchains, CI workflows, artifacts, release metadata | Pin/review dependencies, run automated policy checks, identify experimental artifacts, verify checksums/provenance as available |
| TB5 — Vault and audit persistence | Encrypted vault files, envelopes, backups, storage records, audit segments | Parse defensively; authenticate protected data; detect corruption and covered rollback; use atomic persistence |

**Important deployment boundary:** the HTTP service defaults to loopback. Non-loopback binding is refused unless trusted TLS termination is explicitly enabled; that mode also requires configured trusted proxy IPs. The proxy and TLS terminator therefore become part of the deployment trust base.

## 6. Attack surface inventory

1. **Public Rust API:** every method accepting caller-controlled bytes, identifiers, paths, policy definitions, or serialized records.
2. **Parsers and importers:** vault, envelope, backup, credential, policy, audit event/segment, key and signature encodings.
3. **HTTP service:** public health/readiness/metrics/version endpoints; bearer-protected vault, key, encrypt/decrypt, sign/verify, and audit routes; request headers and JSON bodies.
4. **C ABI:** exported functions, raw pointers, NUL-terminated strings, ownership and lifetime rules.
5. **CLI and SDK adapters:** argument parsing, password input, file paths, runtime loading, marshaling, and error presentation.
6. **Storage:** vault and backup files, atomic temporary files, audit directory, metadata, permissions, and filesystem semantics.
7. **Cryptographic and policy operations:** KDF cost, random generation, AEAD, KEM/signature verification, key lifecycle, policy evaluation.
8. **Backends and native code:** OS RNG, software/hardware providers, experimental native backend, FFI and architecture-specific code.
9. **Build and release:** Cargo dependencies, CI actions, generated artifacts, SDK runtime downloads, checksums, and release credentials.
10. **Operational surfaces:** metrics, tracing, server configuration, trusted proxy parsing, rate limiter state, session timeout, and shutdown behavior.

## 7. STRIDE threat register

The ratings below are qualitative prioritization, not measured likelihood or a formal risk score. “Evidence” points to source, tests, or workflows present in the repository. Where a specific abuse case has no dedicated regression test, that gap is stated rather than inferred away.

### 7.1 Spoofing identity (S)

| ID / priority | Abuse case | Existing controls | Repository evidence | Residual risk / follow-up |
|---|---|---|---|---|
| S-01 High | An unauthenticated or remote caller impersonates an HTTP client and invokes vault/key operations. | Protected routes require an exact `Bearer` token; token configuration requires at least 32 bytes; comparison uses constant-time equality. Remote non-loopback binding requires trusted TLS termination and configured trusted proxy IPs. | `crates/nexusq-server/src/main.rs` (`ServerConfig::from_env`, `auth_middleware`, `is_bearer_authorized`); tests `bearer_auth_is_exact_and_constant_time`, `http_health_auth_and_unlock_smoke`, `unauthorized_request_does_not_refresh_session_timeout`. | A single shared bearer token is not per-user identity, scoped credentials, or token rotation. Compromise of the token grants the authority of the server API. Add a documented rotation/secret-storage procedure and consider scoped identities before multi-user deployment. |
| S-02 Medium | An attacker presents a forged or substituted identity credential/signature as authentic. | Verification is performed against the relevant public key and explicit algorithm identifiers; legacy/classical credentials are distinguished from post-quantum credentials in the threat model. | `crates/nexusq-core/src/identity/`; `crates/nexusq-core/src/crypto/sign.rs`; `crates/nexusq-core/src/crypto/pq_sign.rs`; `crates/nexusq-cli/tests/cli_e2e.rs` (`sign_and_verify_roundtrip`, `credential_issue_and_verify`); ML-DSA/ML-KEM vector and Wycheproof tests under `crates/nexusq-ml-dsa/tests/` and `crates/nexusq-ml-kem/tests/`. | Positive round trips do not alone prove rejection of every malformed, wrong-key, revoked, or algorithm-confusion case. Maintain negative verification vectors and explicit revocation/algorithm-binding regression coverage. |
| S-03 High | A caller claims an identity or hardware-attestation state that policy evaluation treats as authenticated. | `PolicyContext` has explicit optional caller and attestation fields; conditions are evaluated only when the required context exists. | `crates/nexusq-core/src/policy/context.rs`; `crates/nexusq-core/src/policy/condition.rs`; `docs/POLICY.md`. | The current session integration does not populate caller identity or hardware-attested context (documented in `docs/POLICY.md`). `RequiresCaller` and `RequiresAttestation` therefore cannot currently establish those guarantees through ordinary session operations. Do not claim per-identity or attestation-based authorization until the context is wired to verified sources and tested end to end. |

### 7.2 Tampering with data or code (T)

| ID / priority | Abuse case | Existing controls | Repository evidence | Residual risk / follow-up |
|---|---|---|---|---|
| T-01 Critical | An attacker modifies ciphertext, swaps keys, changes envelope metadata, or supplies a truncated/unknown-version vault or envelope. | AEAD authentication, key identifiers in associated data, strict version handling, defensive parsing, and fail-closed decryption. | `crates/nexusq-core/src/vault/envelope.rs`; `crates/nexusq-core/src/vault/header.rs`; `crates/nexusq-core/src/crypto/aead.rs`; `crates/nexusq-core/tests/hardening.rs` (`vault_truncation_is_rejected_without_panic`, `vault_unknown_version_is_rejected`, `envelope_ciphertext_corruption_is_rejected`). | Fuzzing reduces parser risk but does not prove absence of parser defects. Keep fuzz targets and malformed-input regression cases current with format changes. |
| T-02 High | An attacker edits, deletes, reorders, or rolls back audit segments to hide or alter operations. | HMAC-authenticated events/segments, previous-segment linkage, encrypted vault-side audit anchor, verification on read/unlock. | `crates/nexusq-core/src/storage/audit_event.rs`; `audit_log.rs`; `audit_segment.rs`; `crates/nexusq-core/tests/storage_e2e.rs` (`tampering_with_the_audit_chain_is_detected`, `audit_rollback_before_last_persisted_state_is_detected`). | The anchor detects rollback only relative to the last persisted vault state. There is no independent external checkpoint or remote immutable log in the current design; an attacker controlling the host and relevant keys/storage may defeat local-only evidence. |
| T-03 High | An attacker changes policy, key status, backup, or stored records to authorize an unintended operation or corrupt recovery. | Typed/versioned records, policy evaluation, authenticated vault persistence, backup integrity checks, and explicit lifecycle operations. | `crates/nexusq-core/src/policy/`; `crates/nexusq-core/src/vault/`; `crates/nexusq-core/src/storage/backup.rs`; `crates/nexusq-core/tests/policy_e2e.rs`; `crates/nexusq-core/tests/storage_e2e.rs` (`backup_and_restore_preserves_the_vault_content`, `backup_uses_a_separate_passphrase`). | Policy configuration and backup/restore remain high-value administrative surfaces. Add negative tests for tampered policy/backup metadata and review authorization around restore/import workflows. |
| T-04 High | A dependency, build action, compiler, CI runner, or release credential is compromised and inserts malicious code or artifacts. | Locked dependency graph, cargo-deny/audit checks, cargo-vet policy, cargo-geiger inventory, CodeQL/manual security workflows, release checksums and experimental-provider separation. | `Cargo.lock`; `deny.toml`; `supply-chain/`; `.github/workflows/ci.yml`; `audit-ci.yml`; `supply-chain-audit.yml`; `codeql.yml`; `docs/THREAT_MODEL.md` supply-chain boundary. | Checksums published beside artifacts on the same release endpoint are not independent publisher signatures. Reproducible builds and independent provenance verification are not complete guarantees; compromised CI/release credentials remain in scope. cargo-vet baseline exemptions are review backlog entries, not third-party audits. |

### 7.3 Repudiation of actions (R)

| ID / priority | Abuse case | Existing controls | Repository evidence | Residual risk / follow-up |
|---|---|---|---|---|
| R-01 High | An operator or compromised client denies a key lifecycle, signing, policy, or envelope operation, or disputes the recorded sequence. | When auditing is enabled, supported security-relevant operations emit structured events; the log is authenticated and verifiable; denied policy operations are recorded. | `crates/nexusq-core/src/storage/audit_event.rs`; `crates/nexusq-core/src/storage/audit_log.rs`; `crates/nexusq-core/tests/storage_e2e.rs` (`full_lifecycle_produces_the_expected_audit_chain`); `crates/nexusq-core/tests/policy_e2e.rs` (`denied_operations_are_recorded_in_the_audit_log`, `audit_records_policy_changed_events`). | Audit is opt-in/configured per vault and current event coverage is not every possible action. A local HMAC chain proves integrity relative to its key, not independent non-repudiation or the real-world identity of an actor. Document audit enablement/retention and add external append-only export/checkpointing for high-assurance deployments. |
| R-02 Medium | A user disputes who issued a request because the service records operation/request metadata but has no distinct authenticated human identity. | HTTP request IDs, operation names, status/duration metrics and audit events provide operational correlation. | `crates/nexusq-server/src/main.rs` (`observability_middleware`, `operation_name`); `crates/nexusq-core/src/observability.rs`. | A shared bearer token and request ID are not a durable human identity or signed client attribution. Avoid treating operational telemetry as proof of individual authorization. |

### 7.4 Information disclosure (I)

| ID / priority | Abuse case | Existing controls | Repository evidence | Residual risk / follow-up |
|---|---|---|---|---|
| I-01 Critical | An attacker obtains a vault, backup, or storage file and attempts to recover private keys or plaintext offline. | Password-derived KEK using Argon2id and authenticated encryption; wrapped key material; separate backup passphrase; restrictive file permissions and documented storage guidance. | `crates/nexusq-core/src/vault/`; `crates/nexusq-core/src/storage/backup.rs`; `crates/nexusq-core/tests/hardening.rs` (`vault_wrong_password_never_unlocks`); `crates/nexusq-core/tests/storage_e2e.rs` (`backup_uses_a_separate_passphrase`); `docs/STORAGE.md`. | Security depends on password entropy, KDF parameters, host/filesystem behavior, and backup handling. Vault metadata and usage patterns remain visible; flash overwrite is best-effort. |
| I-02 High | Secrets leak through logs, metrics, error responses, process memory, crash dumps, or long-lived buffers. | Zeroizing wrappers are used for selected sensitive buffers; audit events exclude key material/plaintext by design; HTTP observability exposes bounded metadata and has a test asserting the password is not present in metrics. | `crates/nexusq-server/src/main.rs` (`UnlockRequest`, `EncryptRequest`, observability tests); `crates/nexusq-core/src/storage/audit_event.rs`; `docs/SECURITY_MODEL.md` §7.4 and §8. | Zeroization is best-effort and cannot defeat a privileged host, debugger, malware in the user's context, swap/core dumps, or compiler/platform copies. Review every new log/metric/error field for secret leakage. |
| I-03 High | A network observer reads bearer tokens, passwords, plaintext, or ciphertext in transit. | Loopback is the default bind address; non-loopback service exposure requires explicitly trusted TLS termination and a trusted proxy allowlist; protected routes require bearer authentication. | `crates/nexusq-server/src/main.rs` (`DEFAULT_ADDR`, `ServerConfig::from_env`, protected routes); `docs/DEPLOYMENT.md`. | TLS is terminated outside this server in remote mode. The deployment's proxy, certificate configuration, forwarding rules, and network segmentation must be secured independently. Public health/readiness/metrics endpoints reveal limited service metadata. |
| I-04 Medium | A local or remote caller learns sensitive operational state from errors or observability endpoints. | Public health/metrics responses are intentionally narrow; errors and metrics avoid returning secret payloads; request bodies are size-limited. | `crates/nexusq-server/src/main.rs` (`health`, `ready`, `metrics`, `ApiError`); server observability tests. | Metrics and readiness still reveal service/provider state. Keep endpoints on trusted networks where possible and review newly exposed labels, paths, and error details. |

### 7.5 Denial of service (D)

| ID / priority | Abuse case | Existing controls | Repository evidence | Residual risk / follow-up |
|---|---|---|---|---|
| D-01 High | A client floods HTTP routes, sends oversized JSON bodies, or uses expensive operations to exhaust CPU/memory. | Per-client in-memory request rate limiter (default 60 requests per 60 seconds), bounded limiter entries, configurable request-body cap (default 1 MiB), authentication on protected routes, and session inactivity timeout. | `crates/nexusq-server/src/main.rs` (`RateLimiter`, `DefaultBodyLimit`, middleware); tests `rate_limiter_enforces_window_limit`, `rate_limiter_evicts_oldest_client_at_capacity`, `http_health_auth_and_unlock_smoke`. | The limiter is process-local and not a distributed quota; IP identity depends on correct proxy trust. Authenticated clients can still consume expensive KDF/crypto work within configured limits. Rate limiting is not a complete DoS defense. |
| D-02 High | Malformed or deeply nested files/records trigger excessive allocation, CPU use, panics, or parser stalls. | Length/version validation, fail-closed parsers, regression tests, and cargo-fuzz targets for vault, envelope, backup, audit, credential, policy, and ML-DSA key decoding. | `fuzz/fuzz_targets/`; `crates/nexusq-core/tests/hardening.rs`; `.github/workflows/fuzz-soak.yml`. | The scheduled/sequential soak workflow currently runs vault, envelope, and backup campaigns; existence of other fuzz targets does not mean every target is continuously fuzzed. Add resource budgets and expand continuous campaigns as needed. |
| D-03 Medium | Disk exhaustion, filesystem failure, or audit persistence failure prevents operations or recovery. | Atomic write patterns and fail-closed behavior for relevant security operations; audit write failures are treated as operation failures where audit is required. | `crates/nexusq-core/src/storage/atomic.rs`; `crates/nexusq-core/src/storage/audit_log.rs`; `docs/STORAGE.md`; `docs/SECURITY_MODEL.md` §7.7. | No application can guarantee storage availability. Capacity monitoring, backups, retention policy, and filesystem selection remain operator responsibilities; audit retention is an open design item. |

### 7.6 Elevation of privilege (E)

| ID / priority | Abuse case | Existing controls | Repository evidence | Residual risk / follow-up |
|---|---|---|---|---|
| E-01 Critical | A caller uses a key for an unauthorized purpose, bypasses a deny rule, or invokes a privileged lifecycle operation. | Typed key purposes/statuses, explicit policy operations/targets/conditions, deny precedence, and session-level enforcement for covered auditable operations. | `crates/nexusq-core/src/policy/`; `crates/nexusq-core/src/vault/purpose.rs`; `crates/nexusq-core/tests/policy_e2e.rs` (`empty_policy_set_denies_everything`, `explicit_allow_permits_only_the_named_operation`, `explicit_deny_overrides_an_allow`, `policies_persist_across_lock_and_unlock`). | **Critical configuration nuance:** `policies = None` means the policy engine is not enabled and operations are permitted under historical behavior; attaching even an empty set enables default-deny. Also, caller and hardware-attestation context are not currently populated by session integration. Operators must not assume identity-bound policy enforcement without explicitly enabling policies and accounting for these limitations. |
| E-02 High | A malformed foreign-function call or unsafe boundary corrupts memory or bypasses core invariants. | Core crate forbids unsafe Rust; unsafe code is isolated to narrow platform/FFI boundaries; C ABI validates null pointers and UTF-8 and documents pointer ownership/lifetime preconditions. | `crates/nexusq-core/src/lib.rs` (`#![forbid(unsafe_code)]`); `crates/nexusq-c/src/lib.rs`; C ABI unit tests for null/invalid UTF-8 inputs and `nexusq_string_free`. | `CStr::from_ptr` still requires a valid readable NUL-terminated pointer; arbitrary invalid/dangling pointers are undefined behavior and cannot be made safe by null/UTF-8 checks. C callers must obey the ABI contract. The unsafe inventory is a review aid, not proof of memory safety. |
| E-03 High | An attacker causes a silent downgrade or substitution of an experimental/native crypto provider. | Explicit provider metadata and experimental flag; ordinary SDK runtime artifacts use the default provider; experimental native artifacts use a separate workflow and are not silently substituted. | `crates/nexusq-core/src/hardware/`; `crates/nexusq-native-backend/`; `.github/workflows/native-runtime.yml`; `.github/workflows/native-backend-gate.yml`; `docs/THREAT_MODEL.md` native runtime distribution boundary. | Native backend remains opt-in and unaudited. Consumers must inspect provider metadata and verify release provenance; availability does not imply certification or production readiness. |
| E-04 High | A compromised dependency or CI/release identity gains code execution in downstream applications. | Dependency policy and inventory workflows, pinned tool versions, CI checks, separated release workflows, and published checksums. | `Cargo.lock`; `supply-chain/config.toml`; `.github/workflows/supply-chain-audit.yml`; `.github/workflows/audit-ci.yml`; `.github/workflows/ci.yml`. | No dependency scanner can establish that all third-party code is benign. Baseline cargo-vet exemptions are not audits; checksums hosted beside artifacts are not independent signatures; CI/release account compromise remains a residual risk. |

## 8. Cross-cutting assumptions and known gaps

1. **Host integrity:** the OS, kernel, hypervisor, compiler, and hardware firmware may be compromised; software-only deployments do not claim to withstand a privileged host attacker.
2. **Credential strength:** password-derived protection depends on password entropy and the configured KDF parameters. Server bearer tokens must be generated and stored as high-entropy secrets.
3. **Network deployment:** remote HTTP exposure depends on a correctly configured trusted TLS terminator and proxy allowlist. The service does not itself terminate TLS in the described remote-proxy mode.
4. **Policy context:** current session integration does not populate caller identity or hardware-attestation state. A policy set that relies only on those conditions may deny all operations; the absence of an attached policy set is a separate permissive mode.
5. **Audit completeness:** auditing must be enabled and configured. Local HMAC integrity is not external notarization, immutable retention, or proof of human identity.
6. **FFI contract:** C callers must provide valid pointers and respect ownership/lifetime rules. The core's `forbid(unsafe_code)` does not remove the caller's obligations at the ABI boundary.
7. **Availability:** rate limits, request-size limits, fuzzing, and fail-closed handling reduce risk but do not guarantee service availability under resource exhaustion.
8. **Supply chain:** pinned versions, audit policy, and checksums reduce risk but do not prove dependency trust, reproducible builds, release-account integrity, or independent artifact provenance.

## 9. Evidence and verification map

| Security area | Primary evidence | CI / workflow evidence |
|---|---|---|
| Core regression coverage | `crates/nexusq-core/tests/hardening.rs`; `policy_e2e.rs`; `storage_e2e.rs` | `.github/workflows/ci.yml` (`cargo test --workspace --locked`) |
| CLI behavior | `crates/nexusq-cli/tests/cli_e2e.rs` | `.github/workflows/ci.yml` |
| HTTP authentication, rate limiting, session expiry, observability | Unit/integration tests in `crates/nexusq-server/src/main.rs` | `.github/workflows/ci.yml` |
| C ABI boundary | Unit tests in `crates/nexusq-c/src/lib.rs` | `.github/workflows/ci.yml` |
| Parser fuzzing | `fuzz/fuzz_targets/` | `.github/workflows/fuzz-soak.yml` (vault, envelope, backup soak campaigns) |
| Dependency trust / unsafe inventory | `supply-chain/`, `deny.toml`, `Cargo.lock` | `.github/workflows/audit-ci.yml`; `.github/workflows/supply-chain-audit.yml` |
| Static analysis | Repository source and workflow configuration | `.github/workflows/codeql.yml` (manual dispatch); `.github/workflows/dylint-crypto.yml` |
| Native provider separation | `crates/nexusq-native-backend/`, provider metadata | `.github/workflows/native-runtime.yml`; `.github/workflows/native-backend-gate.yml` |

A workflow definition is evidence of an intended automated check, not proof that a particular commit passed it. For a release or audit package, retain the corresponding GitHub Actions run URL, commit SHA, artifact, and reviewer decision.

## 10. Risk treatment and review cadence

- **Mitigate:** T-01–T-04, S-01, E-01–E-04, I-01–I-03, and D-01–D-03 through the controls and regression evidence above.
- **Accept with explicit limitations:** privileged host compromise, malware in the user's security context, physical extraction without hardware protection, residual side channels, incomplete DoS resistance, and local-only audit anchoring; see `THREAT_MODEL.md` §§7–9.
- **Track as follow-up:** caller/attestation context wiring; shared bearer-token lifecycle and scoping; external audit export/checkpointing; negative identity/credential verification coverage; expanded fuzz soak coverage; independent release provenance; and explicit operational backup/retention procedures.

Review this document whenever a public entry point, trust boundary, crypto/provider selection, key lifecycle, authorization behavior, persistence format, build/release workflow, or relevant security test changes. Update the threat row, control, evidence path, and residual-risk statement in the same change. Re-review at least once per release milestone.

## 11. References

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — adversaries, assets, trust boundaries, in-scope/out-of-scope threats, assumptions, and accepted risks
- [`SECURITY_MODEL.md`](SECURITY_MODEL.md) — security guarantees, vault/session model, authorization, failure handling, and audit chain
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — system layers and module boundaries
- [`POLICY.md`](POLICY.md) — policy semantics and current context limitations
- [`KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md) — key lifecycle
- [`STORAGE.md`](STORAGE.md) — persistence and filesystem assumptions
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — deployment configuration and network exposure
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [Microsoft STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

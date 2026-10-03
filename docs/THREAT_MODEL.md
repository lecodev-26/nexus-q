# NEXUS-Q — Threat Model

> **Status:** Living reference document
> **Audience:** Contributors, reviewers, security auditors
> **Scope:** Adversaries, assets, trust boundaries, out-of-scope threats

---

## 1. Purpose

This document defines **what NEXUS-Q protects, against whom, and under what
assumptions**. It is the contract between NEXUS-Q and its users: if a
threat is listed here as "covered", we commit to defending against it; if
a threat is listed as "out of scope", we explicitly do not.

Any change to cryptographic primitives, storage formats, or policy engine
must be validated against this document.

---

## 2. Assets

We protect the following assets, in order of sensitivity:

| ID  | Asset                                    | Sensitivity | Notes |
|-----|------------------------------------------|-------------|-------|
| A1  | Private keys (long-term)                 | Critical    | Identity, signing, KEM |
| A2  | Symmetric data keys (wrapped)            | Critical    | Short-lived, per-envelope |
| A3  | Plaintext user data                      | High        | Files, messages, credentials |
| A4  | Identity metadata and credentials        | High        | Who is who, public keys |
| A5  | Vault metadata (structure, policies)     | Medium      | Can leak usage patterns |
| A6  | Audit log integrity                      | Medium      | Tamper-evidence matters |
| A7  | System availability (no DoS)             | Medium      | Fail-closed, not fail-crash |

**A1 and A2 are the crown jewels.** If a private key or a wrapped data key
leaks, everything encrypted under it is compromised retroactively. Design
decisions prioritize protecting these over everything else.

---

## 3. Adversaries

We consider the following adversary models. They are cumulative: a stronger
adversary has all the capabilities of the weaker ones.

### 3.1 Passive network adversary (A-net)

- **Capabilities:** observes, records, and replays network traffic.
- **Cannot:** modify traffic, compromise endpoints.
- **Goal:** learn secret material, correlate identities, break confidentiality.
- **NEXUS-Q defense:** all network-facing operations use authenticated
  encryption; session keys via post-quantum KEM; no plaintext secrets over
  the wire (Fase 14).

### 3.2 Active network adversary (A-active)

- **Capabilities:** injects, modifies, drops, replays, and forges traffic.
- **Cannot:** compromise endpoints directly.
- **Goal:** impersonate parties, tamper with messages, force downgrade.
- **NEXUS-Q defense:** signatures on all messages; AEAD with unique nonces;
  no protocol downgrade paths; strict version negotiation.

### 3.3 Local unprivileged attacker (A-local)

- **Capabilities:** runs code on the same machine as the target process,
  but as a different (unprivileged) user.
- **Cannot:** read process memory of the victim user, modify system binaries.
- **Goal:** steal files, read the vault on disk, extract keys via side
  channels, hijack IPC.
- **NEXUS-Q defense:** vault files encrypted at rest; keys wrapped under a
  key derived from user credentials; IPC authentication; side-channel
  hardening (Fase 16).

### 3.4 Local privileged attacker (A-root)

- **Capabilities:** full control of the OS (root, kernel modules, ptrace).
- **Goal:** everything.
- **NEXUS-Q defense:** **partial**. See section 5. A rooted OS is
  fundamentally hostile. We mitigate with hardware backing (TPM, Secure
  Element) when available, but we do not claim security against A-root on
  a pure-software deployment.

### 3.5 Malware (A-malware)

- **Capabilities:** runs on the user's device with the user's privileges
  (keylogger, screen capture, clipboard sniffer, process injection).
- **Goal:** exfiltrate keys, plaintext, credentials.
- **NEXUS-Q defense:** **partial**. We minimize the window during which
  secrets are in memory, zeroize aggressively, and support hardware-backed
  operations. We do not claim to defeat a keylogger during password entry.

### 3.6 Physical attacker (A-physical)

- **Capabilities:** has physical possession of the device.
- **Goal:** extract keys from storage, cold-boot attack, chip-off.
- **NEXUS-Q defense:** **partial**. Encrypted vault on disk; keys derived
  from user credentials not stored alongside data. Full defense requires
  hardware (Secure Element, TPM with PIN, anti-tamper).

### 3.7 Side-channel observer (A-side)

- **Capabilities:** measures timing, power, cache behavior, electromagnetic
  emissions of cryptographic operations.
- **Goal:** recover secrets without exploiting a logical bug.
- **NEXUS-Q defense:** **partial**. We select constant-time primitives,
  document which operations are constant-time, and forbid branching on
  secrets in our code. Full defense against physical side channels
  requires hardware.

### 3.8 Quantum adversary (A-quantum)

- **Capabilities:** has a cryptographically relevant quantum computer
  (CRQC), or records traffic today to decrypt it later (harvest-now,
  decrypt-later).
- **Goal:** break classical public-key cryptography (RSA, ECDH, ECDSA).
- **NEXUS-Q defense:** **primary design goal**. Current key-establishment
  uses the ML-KEM-768/X25519 hybrid. Identity signatures currently use
  Ed25519, so current signature operations are classical; ML-DSA/SLH-DSA
  support is planned. Symmetric primitives use 256-bit keys.

### 3.9 Supply-chain adversary (A-supply)

- **Capabilities:** compromises dependencies, build tools, CI/CD, or the
  release pipeline.
- **Goal:** inject malicious code into NEXUS-Q.
- **NEXUS-Q defense:** minimal dependencies; `cargo audit` and SBOM in CI;
  reproducible builds (aspirational); signed releases; review of every
  dependency change (Fase 15).

---

## 4. Trust boundaries

A trust boundary is a line where data or control passes from a less trusted
zone to a more trusted zone. Every boundary is a potential attack surface.

```

┌──────────────────────────────────────────────────────────┐
│  UNTRUSTED                                                │
│  Network, other apps, other users, the OS itself          │
└───────────────────────────┬──────────────────────────────┘
│  TB1: Public API
┌───────────────────────────▼──────────────────────────────┐
│  TRUSTED (with validation)                                │
│  NEXUS-Q library — all inputs validated, fail closed      │
└───────────────────────────┬──────────────────────────────┘
│  TB2: Backend traits
┌───────────────────────────▼──────────────────────────────┐
│  SEMI-TRUSTED                                             │
│  Software backend (our code)                              │
│  Hardware backend (vendor firmware — trust with caution)  │
└───────────────────────────┬──────────────────────────────┘
│  TB3: Platform syscalls
┌───────────────────────────▼──────────────────────────────┐
│  UNTRUSTED (platform)                                     │
│  OS, drivers, filesystem, RNG, devices                    │
└──────────────────────────────────────────────────────────┘

```

**Rules:**

- **TB1 (Public API):** every byte crossing this boundary is untrusted.
  All parsing, deserialization, and length handling must be defensive.
  Malformed input must return an error, never panic or hang.
- **TB2 (Backend traits):** backends are treated as semi-trusted. Software
  backends are our own code (trusted). Hardware backends involve vendor
  firmware — we trust them only as far as we can verify (attestation).
- **TB3 (Platform syscalls):** the OS is not trusted. We use it, but we
  assume it can lie (e.g., a compromised `getrandom` could return
  predictable bytes). Hardware attestation is our tool to detect this
  where it matters.

---

## 5. Attack surface

Every entry point where an attacker could inject input, influence control
flow, or observe behavior.

### 5.1 Parsers (highest priority)

- Envelope format (`NQEV1`) — parsed on every decrypt
- Vault file format — parsed on every unlock
- Storage DB format — parsed on every open
- Key serialization (public and private) — parsed on import
- Audit log entries — parsed on verification
- Policy definitions — parsed on evaluation

**Mitigation:** fuzzing (Fase 15), strict length checks, version byte
validated first, no unbounded allocation from untrusted lengths.

### 5.2 Public API

- Every function that takes caller-provided bytes
- Every error path (must not leak information beyond what is needed)
- Every configuration option

**Mitigation:** type-safe API (see section 1.4 of `ARCHITECTURE.md`),
no raw `Vec<u8>` where a typed value is possible.

### 5.3 Storage layer

- File paths (traversal, symlink attacks)
- File permissions (world-readable vault?)
- Concurrent access (TOCTOU between check and write)
- Partial writes (crash mid-write)

**Mitigation:** atomic writes (write-temp-then-rename), permissions
checked on open, no following symlinks for sensitive files.

### 5.4 Randomness sources

- OS RNG (can be compromised or return low entropy)
- Hardware RNG (can be faulty or malicious)

**Mitigation:** health checks (Fase 8), mixing multiple sources when
available, fail closed if entropy is insufficient.

### 5.5 Time

- System clock can be manipulated by an attacker with local access.
- Expiration checks, not-before checks, and audit timestamps all rely on it.

**Mitigation:** never trust the system clock for security-critical
decisions alone; use monotonic counters where possible; document the
limitation.

### 5.6 Network (Fase 14+, not yet)

- TLS/IPC endpoints, authentication, replay protection, downgrade attacks.

**Mitigation:** post-quantum KEM for session keys, signatures on messages,
strict version negotiation.

### 5.7 Hardware backends (Fase 7+)

- TPM, HSM, Secure Element — vendor firmware is a black box.
- Attestation is our only leverage: if the device cannot prove it is
  running the software we expect, we refuse to use it for high-value
  operations.

**Mitigation:** attestation required for high-value keys; documented trust
assumptions per vendor.

### 5.8 Build and dependency chain

- Crates.io packages, `Cargo.lock`, CI runners, release artifacts.

**Mitigation:** minimal dependency tree; every dependency reviewed;
`cargo audit`, `cargo deny`, SBOM in CI; signed releases.

---

## 6. Threats explicitly in scope

For each of the following, NEXUS-Q commits to defending. If we fail, it is
a vulnerability.

| ID   | Threat                                       | Defense |
|------|----------------------------------------------|---------|
| T-01 | Ciphertext tampering                         | AEAD + authentication tag |
| T-02 | Key substitution (wrong key accepted)        | Key IDs bound into AEAD associated data |
| T-03 | Replay of old ciphertext                     | Nonces + versioned envelopes + anti-rollback |
| T-04 | Forged signatures                            | PQC signature verification; no downgrade |
| T-05 | Harvest-now-decrypt-later                    | PQC KEM for all key establishment |
| T-06 | Vault file theft (offline)                   | Argon2id-derived KEK + AEAD |
| T-07 | Malicious vault file (parser attack)         | Fuzzed parsers, strict validation |
| T-08 | Key misuse (wrong operation for key purpose) | Policy engine enforces purpose |
| T-09 | Audit log tampering                          | Chained MAC; verification on read |
| T-10 | Silent downgrade of algorithm                | Version byte + strict algorithm binding |
| T-11 | Weak or predictable randomness               | TRNG + OS CSPRNG mixing, health checks, fail-closed |
| T-12 | Cross-version format confusion               | Version byte first; reject unknown |

### T-11 in detail: randomness

Randomness underpins every key, nonce and salt in NEXUS-Q. If an
attacker can predict a key's bytes, every promise the key makes is
void. The defense has three layers:

1. **Two independent sources.** When a hardware TRNG is accessible,
   NEXUS-Q reads from it *and* from the OS CSPRNG, concatenates both
   streams, and runs them through HKDF-SHA256. A fault in either
   source does not weaken the output, because the other still
   contributes entropy. Only simultaneous failure of both would
   degrade the result.

2. **Health checks on the TRNG.** Every TRNG sample is validated
   before use: correct length, non-constant, at least 16 distinct
   byte values, different from the previous sample. A failing sample
   marks the TRNG unusable and subsequent draws skip it. The checks
   are basic; they catch an obviously broken source, not a subtle
   one. Regulatory deployments must run AIS 31 / SP 800-90B on the
   actual hardware.

3. **Fail closed.** If the OS CSPRNG fails, the operation fails.
   NEXUS-Q never falls back to a weaker source than the one that
   failed. Absence of a TRNG is not a failure: it degrades the source
   to "OS only", which is already as strong as what most software
   uses.

Platforms without access to a raw TRNG (Termux without root,
unprivileged Linux processes, most desktop environments) run with
the OS CSPRNG alone. This is documented, not hidden: see
`docs/CRYPTOGRAPHY.md` §4.1.

---

## 7. Threats explicitly out of scope

These are **not** defended against in v1.0. Documenting them prevents users
from overestimating NEXUS-Q's guarantees.

| ID   | Threat                                          | Reason |
|------|--------------------------------------------------|--------|
| O-01 | Compromised OS / kernel (root)                   | Cannot defend on general-purpose OS; mitigated by hardware |
| O-02 | Keylogger or screen capture during password entry | Client-side concern; mitigated by hardware input |
| O-03 | Cold-boot / RAM extraction with physical access   | Requires hardware anti-tamper; mitigated by Secure Element |
| O-04 | Electromagnetic / power side-channel attacks      | Requires physical proximity; constant-time code reduces but not eliminates |
| O-05 | Malicious hardware RNG                           | Health checks catch faulty, not adversarial, RNG |
| O-06 | Compromised compiler / build tool                | Mitigated by reproducible builds, not eliminated |
| O-07 | Quantum computer breaking symmetric crypto (256-bit) | Not feasible with Grover for 256-bit key |
| O-08 | Rubber-hose cryptanalysis (coercion)              | Not a technical problem |
| O-09 | Supply-chain attack on a dependency              | Mitigated by review + SBOM; cannot guarantee third-party code |
| O-10 | Zero-day in the OS, filesystem, or hardware      | Cannot defend against unknown platform bugs |
| O-11 | Denial of service by resource exhaustion         | Partially mitigated; full DoS defense out of scope for v1.0 |
| O-12 | Multi-tenant cloud / hypervisor attacks          | Deployment concern; NEXUS-Q does not assume hostile hypervisor |

**Key point:** many of these require **hardware** to be fully addressed.
Where a hardware backend (TPM, Secure Element, HSM) exists and is
configured, the corresponding mitigation applies. On a software-only
deployment, they remain out of scope.

---

## 8. Assumptions

For the threats in section 6 to be mitigated, the following must hold:

- **A-1:** The Rust compiler and standard library are not malicious.
- **A-2:** The cryptographic libraries we depend on (RustCrypto, PQClean,
  or equivalents) are correct and not backdoored.
- **A-3:** The OS RNG (`getrandom`, `/dev/urandom`, Android `getrandom`)
  returns at least 256 bits of entropy per request when healthy.
- **A-4:** The user's password (when used) has sufficient entropy, or the
  KDF parameters are strong enough to compensate.
- **A-5:** The device's clock is approximately correct (not necessarily
  precise — we never rely on sub-second accuracy for security).
- **A-6:** When a hardware backend is used, its attestation is truthful.

If any of these assumptions fails, the corresponding mitigation may fail.

---

## 9. Accepted risks

Risks we know about, cannot fully mitigate in v1.0, and explicitly accept:

### R-1: Password-based vault unlock is only as strong as the password

Argon2id with strong parameters raises the cost of offline attacks, but a
weak password still falls. **Mitigation:** document recommended parameters,
refuse obviously weak passwords in the CLI, but never claim to make weak
passwords secure.

### R-2: Vault metadata leaks usage patterns

File sizes, number of keys, timestamps, and operation frequencies are
visible to an attacker with disk access. **Mitigation:** none in v1.0.
Padding is a v1.x consideration.

### R-3: Side-channel resistance is best-effort on general-purpose CPUs

We use constant-time primitives and forbid secret-dependent branching in
our code, but we cannot control the compiler, the CPU, or the cache
hierarchy. **Mitigation:** document per-primitive guarantees; hardware
backends provide stronger isolation.

### R-4: Backup and recovery may weaken security

To allow recovery, users may export wrapped keys. That export, if stored
poorly, becomes an attack vector. **Mitigation:** recommend paper backups
of recovery codes, never online backups of private keys.

### R-5: A compromised dependency means a compromised NEXUS-Q

We minimize dependencies and audit them, but we cannot prove a
third-party crate is backdoor-free. **Mitigation:** SBOM, `cargo audit`,
pinned versions, reproducible builds (aspirational).

### R-6: Physical access defeats software-only protection

An attacker with physical access and enough time can extract keys from
RAM (cold boot), from disk (offline attack on the vault), or from the CPU
(fault injection). **Mitigation:** recommend hardware backends for
high-value deployments.

---

## 10. Security guarantees

What NEXUS-Q **does** claim, in plain terms:

1. **Confidentiality of data at rest**, assuming the vault key is not
   compromised: an attacker with the vault file cannot read plaintext.
2. **Integrity of data at rest**: any modification of an encrypted file
   is detected before any plaintext is returned.
3. **Authenticity of signatures**: a signature verifies only if it was
   produced by the holder of the corresponding private key, assuming the
   signature scheme is unbroken.
4. **Forward secrecy of session keys** (Fase 14+): a compromised
   long-term key does not reveal past session keys.
5. **Post-quantum key-establishment resistance** through the implemented
   ML-KEM-768/X25519 hybrid, assuming the underlying schemes and construction
   remain secure. Current Ed25519 signatures are classical and are not
   post-quantum secure.
6. **Tamper-evidence of the audit log**: any modification of a past
   entry invalidates the chain.
7. **Fail-closed behavior**: on any error, no partial plaintext is
   returned.

What NEXUS-Q **does not** claim:

- Security against a compromised OS, kernel, or hypervisor.
- Security against a keylogger or screen capture.
- Security against an attacker with prolonged physical access and no
  hardware-backed key storage.
- Security against a user who chooses a weak password and disables all
  hardware protections.
- Security of downstream applications that misuse the API.

---

## 11. Review and evolution

This threat model is a **living document**. It is reviewed:

- At the end of Fase 0 (this document)
- Before each major release (v1.0, v1.1, ...)
- Whenever a new class of adversary becomes relevant (e.g., a new
  side-channel technique, a new quantum result)
- Whenever the architecture changes in a way that affects trust boundaries

Changes to this document are versioned in Git and follow the same review
process as code changes.

---

## 12. References

- `docs/ARCHITECTURE.md` — system architecture
- `docs/CRYPTOGRAPHY.md` — algorithms and rules
- `docs/SECURITY_MODEL.md` — detailed security model
- `docs/KEY_MANAGEMENT.md` — key lifecycle
- NIST Post-Quantum Cryptography standardization (FIPS 203, 204, 205)
- OWASP Cryptographic Storage Cheat Sheet
- "Cryptography Engineering" — Ferguson, Schneier, Kohno

---

*End of document.*

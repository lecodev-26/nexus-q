# AXIOM NEXUS-Q — Security Model

> **Status:** Draft (Fase 0)
> **Audience:** Contributors, security reviewers, architects
> **Scope:** Security guarantees, trust components, session and audit model

---

## 1. Purpose

This document specifies **the security model of NEXUS-Q**: what it means
for the system to be "secure", which components are trusted, how sessions
and authorization work, and how the audit chain provides tamper-evidence.

Where `THREAT_MODEL.md` says "against whom we protect", this document
says "how the protection is organized".

---

## 2. Definitions

### 2.1 What "secure" means here

NEXUS-Q is **secure** if, under the assumptions in
`THREAT_MODEL.md` §8 and the trust model in §3 below:

1. Confidentiality holds: data encrypted under a key cannot be read by
   anyone who does not possess the key.
2. Integrity holds: any modification of protected data is detected
   before the data is used.
3. Authenticity holds: signatures verify only for the actual signer.
4. Availability holds: operations fail closed, never open.
5. Auditability holds: security-relevant events are recorded and cannot
   be tampered with undetectably.

Each of these is defined more precisely in the sections that follow.

### 2.2 Non-goals

NEXUS-Q does **not** attempt to be:

- A general-purpose OS security layer (no SELinux, no seccomp policy).
- A network security layer (no firewall, no TLS termination).
- A user authentication system (it consumes credentials, does not
  provide them).
- A code-signing or sandboxing layer for other applications.

---

## 3. Trust model

### 3.1 Trusted components

The following components are **trusted** in the security model:

| Component                | Why trusted |
|--------------------------|-------------|
| NEXUS-Q library code     | Our code; reviewed, tested, fuzzed |
| Rust standard library    | Widely reviewed; part of our TCB |
| Chosen crypto crates     | Audited, minimal, pinned (see CRYPTOGRAPHY.md) |
| OS CSPRNG (when healthy) | Foundation of all randomness |
| Hardware backends        | Trusted when attested; see §3.3 |

### 3.2 Untrusted components

The following are **not trusted**:

| Component | Notes |
|-----------|-------|
| Network             | Assume hostile; all inputs validated |
| Filesystem          | Assume attacker can read/write if disk is stolen |
| Other processes     | Same machine, different user = hostile |
| The OS itself       | Assume possible compromise; hardware mitigations apply |
| User input          | Assume malformed or malicious |
| System clock        | Assume can be manipulated by local attacker |

### 3.3 Hardware trust assumptions

When a hardware backend is used:

- We trust it **only** if attestation succeeds (Fase 9).
- Attestation is only as good as the hardware vendor's implementation.
- We document per-vendor trust assumptions.
- We do not trust "trust us, we're secure" claims; attestation must be
  cryptographic and verifiable.

### 3.4 Trust boundary recap

From `ARCHITECTURE.md` §4, the four layers are:

- **L4 Consumers** (untrusted — public API validates everything)
- **L3 Core** (trusted — our code)
- **L2 Backends** (semi-trusted — software is our code, hardware is
  attested)
- **L1 Platform** (untrusted — OS, drivers, devices)

---

## 4. Vault states and sessions

The vault has a small state machine, and access is granted via sessions.

### 4.1 Vault states

| State       | Meaning |
|-------------|---------|
| LOCKED      | No KEK in memory. Only metadata is readable. |
| UNLOCKED    | At least one KEK is in memory. Operations allowed per policy. |
| SEALED      | Temporarily locked; no new operations, existing ones finish. |
| COMPROMISED | Detected tamper or policy violation; operations denied until admin intervention. |

**Transitions:**

```

LOCKED ──unlock──► UNLOCKED ──lock──► LOCKED
│
├──seal──► SEALED ──unseal──► UNLOCKED
│
└──tamper──► COMPROMISED (terminal until reset)

```

### 4.2 Sessions

A session is the unit of access. Created when the vault is unlocked with
a credential, ends when:

- The user explicitly locks the vault.
- The session times out (configurable, default 15 minutes of inactivity).
- The process exits.
- The vault enters COMPROMISED state.

Sessions carry:

- The identity that unlocked the vault.
- The set of KEKs currently loaded.
- The authorization scope (which keys, which operations).

Sessions do **not** carry:

- Raw password material (zeroized after KEK derivation).
- DEKs (loaded on demand, zeroized after use).
- Long-lived tokens.

### 4.3 Session termination

On session end:

1. All DEKs in memory are zeroized.
2. All temporary buffers are zeroized.
3. The KEKs are removed from memory (zeroized).
4. The session token is invalidated.
5. An audit event `SESSION_ENDED` is emitted.

---

## 5. Authentication and authorization

### 5.1 Authentication

Authentication is **how a caller proves who they are**. NEXUS-Q supports:

- **Password-based**: user provides a password; Argon2id derives a KEK
  and proves the user can decrypt the vault.
- **Hardware-backed**: user authenticates to a TPM/SE with a PIN or
  biometric; the hardware then allows access to the handle.
- **Identity-based**: a caller presents a signed challenge using an
  identity key (Fase 6).

Authentication **does not** grant access to specific operations. That is
authorization.

### 5.2 Authorization

Authorization is **what an authenticated caller is allowed to do**. It is
implemented by the **policy engine** (Fase 11).

Policy decisions consider:

- The caller's identity.
- The requested operation (SIGN, DECRYPT, ...).
- The key's purpose and status.
- The current vault state.
- Context: time of day, process, hardware attestation, prior operations.

Default policy: **deny**. Access is granted only by explicit policy.

### 5.3 Separation of authentication and authorization

We keep them separate because:

- A user may be authenticated but not authorized for a specific key.
- Authorization can be changed without re-authenticating.
- Policies can be tested independently of authentication mechanisms.

---

## 6. Failure model

### 6.1 Fail closed

Any error in any security-relevant operation results in **denial**:

- Parse error: reject input, do not partially process.
- Integrity failure: reject data, do not return partial plaintext.
- Policy denial: return error, do not fall back to a weaker operation.
- Hardware failure: deny operation, do not silently use software.
- Randomness failure: refuse to generate keys, do not use low entropy.

### 6.2 No partial results

NEXUS-Q never returns "partial" results. If a decrypt operation fails,
the caller gets an error and **no plaintext**. If a signature
verification fails, the caller gets an error and no "maybe".

### 6.3 Error messages

Error messages must not leak secrets or side information:

- "Decryption failed" — not "padding error" vs "MAC error" (avoids
  padding oracle attacks).
- "Authentication failed" — not "unknown user" vs "wrong password"
  (avoids username enumeration).
- "Operation denied" — not "policy X failed at step Y" (avoids policy
  fingerprinting).

Detailed errors are logged internally (in the audit log) but not returned
to the caller.

### 6.4 Panic policy

The library **must not panic** on untrusted input. All parsing must
return `Result`. Panics are allowed only for:

- Programming errors (unreachable states, invariant violations).
- Failed allocations that indicate OOM.

Any panic reachable from untrusted input is a **bug** and must be fixed.

---

## 7. Audit chain

The audit log is not just a log; it is a **tamper-evident chain**.

### 7.1 Structure

Each audit event contains:

```

event_n = {
index:        n (monotonic, starts at 1),
timestamp:    UTC,
event_type:   e.g., KEY_CREATED,
actor:        identity or process,
subject:      KeyId, VaultId, etc.,
outcome:      success | failure | denied,
context:      minimal, non-secret details,
prev_hash:    H(event_{n-1}),
hash:         H(canonical_serialize(event_n without hash) || prev_hash)
}

```

Where `H` is SHA-256 (see `CRYPTOGRAPHY.md` §4.2), and
`canonical_serialize` produces a deterministic byte sequence (sorted keys,
explicit types, no whitespace).

### 7.2 Tamper detection

To verify the chain:

1. Read events in order.
2. For each event, recompute `hash` and compare.
3. Verify `prev_hash` matches the previous event's `hash`.
4. Verify `index` is strictly increasing.

Any mismatch = tampering detected. The verification is **independent**: it
can be run by any party with read access to the chain.

### 7.3 Append-only

The audit log is **append-only** at the application level:

- No API to modify or delete events.
- Storage layer writes at the end only.
- If truncation is required (retention policy), it is done by
  **snapshotting** (start a new chain with a link to the old chain's
  head), never by deleting from the middle.

### 7.4 What is never logged

- Private keys or any key material.
- Plaintext of user data.
- Passwords or password-derived material.
- Full ciphertexts (only hashes or KeyIds).

### 7.5 What is always logged

Per `KEY_MANAGEMENT.md` §13: `KEY_CREATED`, `KEY_USED`, `KEY_ROTATED`,
`KEY_REVOKED`, `KEY_DESTROYED`, `KEY_EXPORTED`, `KEY_ACCESS_DENIED`,
`VAULT_UNLOCKED`, `VAULT_LOCKED`, `VAULT_SEALED`, `SESSION_ENDED`,
`POLICY_CHANGED`, and any operation that changes security-relevant state.

### 7.6 Failure to log = failure to operate

If the audit log cannot be written (disk full, permission denied), the
**operation is denied**. We do not perform security-relevant operations
without logging them.

---

## 8. Isolation between operations

### 8.1 Key isolation

A DEK is used for exactly one envelope and then zeroized. It is never
reused across envelopes. This limits the impact of any single DEK
compromise.

### 8.2 Session isolation

Each session has its own set of in-memory KEKs and DEKs. Closing a
session zeroizes them. Sessions do not share secret material.

### 8.3 Process isolation

When the NEXUS-Q server runs as a separate process (Fase 14), it:

- Runs as a dedicated user, not root.
- Uses its own memory space (no shared memory with clients unless via
  authenticated IPC).
- Drops privileges after opening its storage.
- Is subject to the OS's process isolation (which we do not control but
  document).

### 8.4 Cryptographic isolation

Different uses of the same master key derive distinct subkeys via HKDF
with distinct `info` strings (see `CRYPTOGRAPHY.md` §5.4). This prevents
cross-protocol attacks.

---

## 9. Comparison with formal models

NEXUS-Q is not formally verified, but it is designed with known models in
mind.

### 9.1 Bell–LaPadula (confidentiality)

In Bell–LaPadula terms:

- Subjects (callers) have a **clearance** (their identity's trust level).
- Objects (keys, data) have a **classification** (their sensitivity).
- "No read up": a caller cannot read data above their clearance.
- "No write down": a caller cannot write data below their clearance.

NEXUS-Q implements this via the policy engine: keys and data carry
sensitivity levels, callers carry identities, and the policy enforces
the lattice. We do not claim to be a full BLP system.

### 9.2 Biba (integrity)

In Biba terms:

- "No read down": a caller cannot read data from a lower integrity
  level (prevents contamination).
- "No write up": a caller cannot write data to a higher integrity level
  (prevents corruption).

NEXUS-Q implements integrity via:

- Signed data (integrity attributed to the signer).
- Audit chain (integrity of the record).
- AEAD tags (integrity of ciphertexts).

### 9.3 Clark–Wilson (commercial integrity)

Clark–Wilson defines integrity through **well-formed transactions** and
**separation of duties**. NEXUS-Q approximates this through:

- Typed API (well-formed transactions).
- Policy engine (separation of duties between key owner and key user).
- Audit log (accountability).

### 9.4 Non-claims

We do **not** claim:

- That NEXUS-Q is verified against any formal model.
- That the implementation is free of bugs.
- That the policies expressible in NEXUS-Q cover every access-control
  need.

We claim that the design is **informed by** these models, and that
deviations from them are documented.

---

## 10. Threat-model alignment

This document implements defenses for the following threats from
`THREAT_MODEL.md`:

- **T-01 (ciphertext tampering)**: fail-closed AEAD.
- **T-04 (forged signatures)**: verification with strict algorithm binding.
- **T-08 (key misuse)**: policy engine + purposes.
- **T-09 (audit log tampering)**: chained hashes.
- **T-10 (silent downgrade)**: explicit algorithm binding, no negotiation.

Threats that the security model **cannot** mitigate in v1.0:

- **O-01 (compromised OS)**: out of scope, mitigated by hardware.
- **O-03 (cold boot)**: out of scope, mitigated by hardware.
- **O-11 (DoS)**: partially mitigated; full DoS defense out of scope.

---

## 11. Open questions

- [ ] Concrete timeout values for sessions (per platform)
- [ ] Retention policy for audit logs (how much to keep, for how long)
- [ ] Whether to support external audit log shipping
- [ ] Formal verification of the policy engine (future work)
- [ ] Snapshot format for audit chain rotation

Resolved in Fase 4 (Vault), Fase 11 (Policy), Fase 18 (Observability).

---

## 12. References

- `docs/THREAT_MODEL.md` — adversaries and threats
- `docs/ARCHITECTURE.md` — module boundaries
- `docs/CRYPTOGRAPHY.md` — hash, KDF, AEAD used here
- `docs/KEY_MANAGEMENT.md` — key lifecycle events
- Bell, D. E., LaPadula, L. J. — "Secure Computer Systems" (1973)
- Biba, K. J. — "Integrity Considerations for Secure Computer Systems" (1977)
- Clark, D. D., Wilson, D. R. — "A Comparison of Commercial and Military
  Computer Security Policies" (1987)
- NIST SP 800-53 — Security and Privacy Controls
- NIST SP 800-92 — Guide to Computer Security Log Management

---

*End of document.*

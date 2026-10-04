# NEXUS-Q — Cryptography

> **Status:** Living reference document
> **Audience:** Contributors, cryptographers, security reviewers
> **Scope:** Algorithms, parameters, and cryptographic rules

---

## 1. Purpose

This document specifies **which cryptographic algorithms NEXUS-Q uses, with
which parameters, and under which rules**. It is the authoritative reference
for anyone implementing or reviewing NEXUS-Q's crypto.

The document records both the cryptographic policy and the current implementation
status. Planned algorithms must not be described as available until they are
implemented, tested and added to `vault::Algorithm`.

---

## 2. The golden rule

> **We do not invent cryptography.**

Concretely, this means:

1. Every primitive is a standardized, peer-reviewed algorithm (NIST, IETF,
   ISO, or equivalent).
2. Every algorithm has a mature implementation in a maintained, audited
   library. We do not write our own AES, our own SHA-3, or our own
   Kyber/Dilithium.
3. We do not modify primitives, key schedules, or padding schemes.
4. We do not compose primitives ad-hoc when a standard composition exists
   (e.g., we use HPKE instead of rolling our own KEM+AEAD+HKDF pipeline
   unless there is a documented reason).
5. If we need a primitive that has no mature Rust implementation, we
   either integrate an audited C library or we do not ship that primitive
   in v1.0.

Any deviation from this rule requires an ADR (Architecture Decision Record)
in the repository and explicit approval in review.

---

## 3. Primitive families

NEXUS-Q uses exactly **six families** of primitives. Nothing else is
allowed in the core.

| Family         | Purpose                                     | Algorithms (see §4) |
|----------------|---------------------------------------------|---------------------|
| Randomness     | Entropy for keys, nonces, salts            | OS RNG, TRNG        |
| Hashing        | Digests, commitments, key derivation input | SHA-2, SHA-3 (implemented); BLAKE2 (not currently exposed) |
| KDF            | Deriving keys from passwords / key material | Argon2id, HKDF     |
| AEAD           | Symmetric authenticated encryption          | AES-256-GCM, ChaCha20-Poly1305 |
| KEM            | Post-quantum key encapsulation              | ML-KEM (Kyber)      |
| Signatures     | Digital signatures                          | Ed25519, ML-DSA-65, SLH-DSA-SHAKE-128f (implemented) |

Anything outside these families (e.g., raw RSA, ECDSA on arbitrary curves,
custom MACs) is forbidden.

---

## 4. Algorithms and parameters

### 4.1 Randomness

**Sources, in order of preference:**

1. **Hardware TRNG**, when accessible. On Linux and Android this is
   typically `/dev/hwrng`, but NEXUS-Q does not assume any particular
   device path: the `TrngSource` trait is the only contract, and a
   platform-specific backend decides how to open it.
2. **OS CSPRNG**, always. On Linux and Android this is
   `getrandom(2)`, which blocks until the kernel pool is initialized;
   `/dev/urandom` is the legacy fallback. On macOS this is
   `SecRandomCopyBytes`; on Windows, `BCryptGenRandom`.

**Mixing.** When a TRNG is available, NEXUS-Q does not use it alone.
The TRNG bytes and the OS bytes are concatenated and run through
HKDF-SHA256 with `info = "nexusq-mixed-rng-v1"`:

    output = HKDF-SHA256(ikm = trng_bytes || os_bytes,
                         salt = none,
                         info = "nexusq-mixed-rng-v1",
                         L = requested_length)

Mixing makes both sources single points of failure only in
combination: a faulty TRNG does not compromise the output because the
OS CSPRNG still contributes; a compromised OS does not compromise the
output because the TRNG still contributes. Both must fail
simultaneously for the output to be weak.

**Health checks.** Every TRNG sample is validated before use:

- Length is exactly the expected sample length.
- Not all bytes identical.
- At least 16 distinct byte values.
- Not identical to the previous sample.

A failing sample marks the TRNG as unusable; subsequent draws skip it
until the failure flag is reset. These checks are **not** NIST SP
800-90B compliant. Deployments that need regulatory-grade assurance
must run the full AIS 31 / SP 800-90B suite against the actual
hardware.

**Fallback policy.** When the TRNG is absent, unavailable, or fails a
health check, the mixed source silently falls back to the OS CSPRNG
alone. The fallback is always to a source of equal or greater strength
than the one that failed; NEXUS-Q never falls back to a weaker source.
If the OS CSPRNG itself fails, the operation fails closed: no key is
generated, no nonce is produced.

**Platforms without TRNG access.** Termux and any unprivileged Linux
process cannot read `/dev/hwrng` directly. On these platforms
`SoftwareTrng::try_open()` returns `None` and the mixed source reduces
to OS-only. This is not a degradation: the OS CSPRNG already mixes
hardware entropy from many sources, including the TRNG, inside the
kernel.

**Requirements:**

- Minimum 256 bits of entropy per key generation.
- Nonces: 96 bits (12 bytes) for AES-GCM and ChaCha20-Poly1305.
- Salts: 128 bits (16 bytes) minimum, 256 bits preferred.

**Forbidden:** `rand::thread_rng()` without explicit CSPRNG backing,
time as a seed, process ID as entropy, user input as entropy, using a
TRNG without mixing, falling back to a weaker source on failure.

### 4.2 Hashing

**Primary:** SHA-256 (FIPS 180-4)

- Used for: general-purpose digests, HKDF (via HMAC-SHA-256), audit chain.
- 256-bit output, 128-bit collision resistance.

**Secondary:** SHA-512 (FIPS 180-4)

- Used for: contexts where a 512-bit digest is required by a standard
  (e.g., some PQC schemes), or where 256-bit collision resistance is
  needed.

**Alternative:** SHA3-256 / SHA3-512 (FIPS 202)

- Used for: domain separation where SHA-2 might be ambiguous, or when a
  sponge construction is required by a standard.

**Alternative:** BLAKE2b / BLAKE2s (RFC 7693)

- Used for: non-cryptographic-critical hashing where speed matters,
  provided it is not used as the sole integrity mechanism.

**Forbidden:** MD5, SHA-1, RIPEMD-160 in any new construction, any
truncated hash below 224 bits.

### 4.3 Key derivation

**Password-based KDF:** Argon2id (RFC 9106)

- Used for: deriving the vault Key Encryption Key (KEK) from a user
  password.
- Parameters (v1.0 minimum):
  - Memory: 64 MiB
  - Iterations: 3
  - Parallelism: 1
  - Salt: 16 bytes, unique per vault
  - Output: 32 bytes
- Parameters are stored alongside the vault (so future versions can
  upgrade the cost).

**Non-password KDF:** HKDF (RFC 5869) with SHA-256

- Used for: deriving subkeys from a master key (e.g., per-purpose keys,
  per-envelope keys derived from a vault master key).
- Info string: always set, always unique per purpose.
- Salt: optional, set when deriving from non-uniform input.

**Forbidden:** PBKDF2 for new passwords (kept only for legacy import, if
ever needed), raw hash as KDF (e.g., `SHA256(password)`), scrypt (Argon2id
is preferred).

### 4.4 AEAD (symmetric encryption)

**Primary:** AES-256-GCM (NIST SP 800-38D)

- Key: 256 bits
- Nonce: 96 bits (12 bytes), **never** reused with the same key
- Tag: 128 bits
- Used for: bulk data encryption, vault contents, wrapped keys

**Alternative:** ChaCha20-Poly1305 (RFC 8439)

- Key: 256 bits
- Nonce: 96 bits (12 bytes), never reused
- Tag: 128 bits
- Used for: platforms without AES hardware acceleration (ARM without
  crypto extensions, some RISC-V configurations)

**Rule:** AEAD is the **only** symmetric encryption mode allowed. No CBC,
no CTR without MAC, no raw stream ciphers without authentication.

**Associated data (AAD):** always includes:

- Version byte of the envelope/format
- Key ID or key derivation context
- Any metadata that must be authenticated but not encrypted

**Nonce policy:**

- 96-bit random nonces are allowed only when the key is used for at most
  2^32 messages (birthday bound for random 96-bit nonces).
- For keys used more frequently, use a counter-based nonce with a
  persistent counter, or derive a fresh key per message via HKDF.
- Nonce reuse with the same key is a **critical vulnerability**; parsers
  and verifiers must reject envelopes that reuse a nonce under the same
  key when detected.

**Forbidden:** AES-CBC, AES-CTR without MAC, AES-GCM with non-96-bit
nonces (unless using the GHASH-based deterministic construction from
SP 800-38D), ECB in any form, any custom mode.

### 4.5 KEM (key encapsulation)

**Primary:** ML-KEM (FIPS 203)

- Formerly known as CRYSTALS-Kyber.
- Security level currently implemented:
  - ML-KEM-768 (NIST level 3) — default
  - ML-KEM-1024 is implemented as a hybrid ML-KEM-1024 + X25519 construction
- Used for: establishing session keys, wrapping data keys, any
  public-key-based key agreement.
- Public key size: 1184 bytes (ML-KEM-768), 1568 bytes (ML-KEM-1024)
- Ciphertext size: 1088 bytes (ML-KEM-768), 1568 bytes (ML-KEM-1024)

**Hybrid mode (recommended for v1.0):**

- Combine ML-KEM-768 with X25519 via HKDF to derive the final key.
- Rationale: if ML-KEM is broken (unlikely but possible), X25519 still
  protects; if X25519 is broken (by a quantum computer), ML-KEM still
  protects. Hybrid = belt and suspenders.
- Standard: follow the draft "Hybrid KEM" from IETF (draft-irtf-cfrg-hybrid-kems)
  when finalized; until then, use the well-understood
  `HKDF(X25519_shared || MLKEM_shared, info="hybrid-kem")`.

**Forbidden:**

- RSA in any form (including RSA-KEM, RSA-OAEP).
- ECDH on P-256, P-384, P-521 for new keys (legacy import only).
- Non-hybrid ML-KEM alone for **long-term** keys where the threat model
  includes a quantum adversary with a long horizon — hybrid is required.
- Any custom KEM construction not published in a peer-reviewed venue.

### 4.6 Digital signatures

**Implemented primary (PQC):** ML-DSA-65 (FIPS 204)

- Formerly CRYSTALS-Dilithium.
- Security levels:
  - ML-DSA-65 (NIST level 3) — **default**
  - ML-DSA-87 (NIST level 5) — for long-term / high-value keys
- Used for: signing documents, credentials, transactions, messages.
- Public key: 1952 bytes (ML-DSA-65), 2592 bytes (ML-DSA-87)
- Signature: 3309 bytes (ML-DSA-65), 4627 bytes (ML-DSA-87)

**Implemented secondary (PQC, stateless hash-based):** SLH-DSA-SHAKE-128f (FIPS 205)

- Formerly SPHINCS+.
- Variants: SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f, and larger.
- Used for: scenarios requiring a hash-based signature (very conservative
  assumptions), or when ML-DSA is considered too new for a specific
  application. Larger signatures, slower, but relies only on hash
  security.
- Not the default; selected per-use-case.

**Currently implemented signature:** Ed25519 (RFC 8032)

- Used for: verifying signatures made by legacy systems; importing
  existing Ed25519 keys for transition.
- Current NEXUS-Q identity operations use Ed25519. Migration to a PQC signature
  scheme is a planned crypto milestone; until then Ed25519 is a classical signature
  and must not be described as post-quantum protection.

**Forbidden:**

- RSA signatures (PKCS#1 v1.5 or PSS).
- ECDSA on any curve for new keys.
- Any signature scheme without a security proof and standardization.

### 4.7 What we do not use, and why

| Algorithm       | Why not |
|-----------------|---------|
| MD5             | Broken collisions since 2004 |
| SHA-1           | Broken collisions since 2017 |
| DES / 3DES      | Too small a key space |
| RC4             | Biased keystream, banned in TLS |
| RSA             | Broken by quantum computers; also historically fragile to implement |
| ECDSA (new keys)| Broken by quantum computers |
| AES-CBC         | Padding oracle attacks |
| AES-ECB         | Leaks plaintext structure |
| Custom ciphers  | We do not invent crypto |
| Custom MACs     | HMAC / Poly1305 exist and are proven |
| Hash-as-KDF     | Not a KDF, trivially brute-forced |
| `rand::thread_rng` | Not guaranteed CSPRNG on all platforms |

---

## 4.8 Current implementation matrix

As of Phase 13, the code actually exposes:

| Primitive | Current status |
|---|---|
| OS randomness | Implemented |
| TRNG + mixed RNG | Implemented behind hardware abstractions |
| SHA-256 / SHA-512 / SHA3-256 / SHA3-512 | Implemented |
| Argon2id / HKDF-SHA256 | Implemented |
| AES-256-GCM / ChaCha20-Poly1305 | Implemented |
| ML-KEM-768 | Implemented |
| ML-KEM-768 + X25519 hybrid | Implemented |
| Ed25519 | Implemented |
| ML-DSA-65 | Implemented |
| SLH-DSA-SHAKE-128f | Implemented |
| ML-KEM-1024 + X25519 | Implemented |
| BLAKE2 | Not exposed by the current public crypto module |

This matrix prevents the design specification from being mistaken for a
claim that every future algorithm is already shipped.

## 5. Composition rules

When combining primitives, we follow **published standards** or
well-understood constructions. Ad-hoc composition is a bug waiting to
happen.

### 5.1 Encrypt-then-MAC vs AEAD

We use **AEAD** (AES-GCM or ChaCha20-Poly1305), which already provides
encryption and authentication in one primitive. We do **not** build our
own "encrypt-then-MAC" constructions from separate AES + HMAC.

### 5.2 KEM + AEAD (envelope encryption)

Standard construction, documented in `STORAGE.md`:

1. Generate a random 256-bit data key `DK`.
2. Encrypt the plaintext with `DK` using AEAD, with AAD = envelope header.
3. Wrap `DK` with the recipient's public key using KEM, or with the
   vault's master key using AEAD.
4. Store: version, algorithm IDs, KEM ciphertext (if used), nonce, tag,
   wrapped DK, ciphertext.

This is **HPKE-like** but simplified for our needs. Where HPKE (RFC 9180)
fits, we prefer HPKE.

### 5.3 Hybrid KEM combiner

Given `(X25519_ss, ML-KEM_ss)`, derive the combined secret as:

```

IKM = X25519_ss || MLKEM_ss
combined = HKDF-SHA256(IKM, info = "nexusq-hybrid-kem-v1", L = 32)

```

The exact construction follows the current IETF draft once finalized.
Until then, this is our documented interim construction.

### 5.4 Key separation

Never use the same key for two purposes. Derive distinct keys via HKDF
with distinct `info` strings:

- `"nexusq-vault-kek-v1"` — vault key encryption key
- `"nexusq-envelope-dk-v1"` — envelope data key
- `"nexusq-audit-chain-v1"` — audit chain key
- `"nexusq-signing-v1"` — signing key
- `"nexusq-kem-v1"` — KEM key

Every use of HKDF in NEXUS-Q MUST have a unique, documented `info` string.

### 5.5 Domain separation everywhere

Any time the same key or the same hash function is used in two contexts,
prepend a distinct domain-separation string. This prevents
cross-protocol attacks.

Examples:

- Signatures include the message type: `"nexusq-sig-doc-v1" || document`
- KEM AAD includes the recipient's KeyId
- Audit entries include the event type as the first field

---

## 6. Parameters and sizes (summary)

| Primitive          | v1.0 default           | Notes |
|--------------------|------------------------|-------|
| Symmetric key      | 256 bits               | AES-256 or ChaCha20 |
| AEAD nonce         | 96 bits (12 bytes)     | Never reused per key |
| AEAD tag           | 128 bits               | Full length |
| Hash output        | 256 bits (SHA-256)     | 512 when needed |
| Argon2id memory    | 64 MiB                 | Per unlock |
| Argon2id iterations| 3                      | |
| HKDF output        | 32 bytes               | Per derived key |
| KEM (default)      | ML-KEM-768 + X25519    | Hybrid |
| Signature default  | Ed25519 (current)      | ML-DSA-65 is implemented |
| Random salt        | 128–256 bits           | Unique per use |

---

## 7. Algorithm versioning

Every algorithm identifier in NEXUS-Q is:

- **Versioned:** `ml-kem-768@v1`, `aes-256-gcm@v1`
- **Explicit:** never inferred from context
- **Stored:** in the envelope header or key metadata
- **Validated:** unknown IDs are rejected (fail-closed)

When a new version of an algorithm is standardized (e.g., ML-KEM-1024
becomes the default), we add a **new identifier**; we never change the
meaning of an existing one.

### 7.1 Deprecation

An algorithm moves through states:

1. **Default:** used for new keys and new data
2. **Supported:** decryptable/verifiable, not used for new data
3. **Deprecated:** still decryptable/verifiable, but logs a warning
4. **Removed:** no longer supported; data must be migrated first

Removal is a **major version** change and requires a documented migration
path (see `STORAGE.md`).

---

## 8. Cryptographic agility

NEXUS-Q is designed so that algorithms can be replaced without breaking
existing data:

- Algorithm IDs are stored with the data, not compiled in.
- Migration tools re-encrypt data under new algorithms when a user opts in.
- No algorithm is assumed to be permanent; even SHA-256 and AES-256 will
  eventually be replaced.

**The one exception:** we do **not** support "algorithm negotiation" in
the sense of "pick the strongest we both know". We support **explicit
algorithm selection** with no silent downgrade. If a peer requests an
algorithm we do not trust, we refuse the operation; we do not fall back.

---

## 9. References

### Standards

- NIST FIPS 203 — ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- NIST FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
- NIST FIPS 180-4 — SHA-2
- NIST FIPS 202 — SHA-3
- NIST SP 800-38D — AES-GCM
- RFC 9106 — Argon2
- RFC 5869 — HKDF
- RFC 8439 — ChaCha20-Poly1305
- RFC 8032 — Ed25519
- RFC 9180 — HPKE
- RFC 7693 — BLAKE2
- draft-irtf-cfrg-hybrid-kems — Hybrid KEMs (in progress)

### Recommended reading

- "Cryptography Engineering" — Ferguson, Schneier, Kohno
- "Real-World Cryptography" — David Wong
- "Serious Cryptography" — Jean-Philippe Aumasson
- NIST Post-Quantum Cryptography FAQ

---

## 10. Open questions

- [ ] Final hybrid KEM construction (pending IETF draft finalization)
- [ ] Whether to support SLH-DSA in v1.0 or defer to v1.1
- [ ] Concrete Argon2id parameters per platform (mobile vs desktop)
- [ ] Nonce management strategy for high-throughput servers
- [ ] Whether to use HPKE directly for envelope encryption

Open items are resolved as the corresponding crypto implementation lands;
implemented behavior is authoritative in the crate source and tests.

---

*End of document.*

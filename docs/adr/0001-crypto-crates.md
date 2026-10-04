# ADR 0001 — Choice of cryptographic crates

- **Status:** Accepted
- **Date:** 2026-09-25
- **Phase:** Fase 2 (Crypto Core)

## Context

NEXUS-Q must implement the primitives specified in `docs/CRYPTOGRAPHY.md`:
randomness, hashing, KDF, AEAD, KEM, and signatures. Per the golden rule,
we do not implement any primitive ourselves — we depend on audited,
maintained crates.

The choice is complicated by post-quantum algorithms being very young.
The NIST standards (FIPS 203/204/205) were finalized in 2024, so most
implementations are 1–2 years old and no PQC crate is yet as mature as
classical ones like `aes-gcm` or `ed25519-dalek`.

Options considered:

- **A:** Pure RustCrypto, including `ml-dsa` at 0.1.x (very unstable).
- **B:** `pqcrypto-*` bindings to PQClean (C), stable but requires a C
  toolchain and builds slowly on mobile.
- **C:** Hybrid pragmatic approach — use mature crates for everything
  available, defer the PQC signature crate until it matures.

## Decision

We adopt **Option C**.

Concretely:

| Family            | Crate                                      | Maturity      |
|-------------------|--------------------------------------------|---------------|
| Randomness        | `getrandom`, `rand_core`                   | Mature        |
| Hashing           | `sha2`, `sha3`                             | Mature        |
| KDF               | `argon2`, `hkdf`                           | Mature        |
| AEAD              | `aes-gcm`, `chacha20poly1305`              | Mature        |
| KEM (PQC)         | `ml-kem` 0.3.x + `x25519-dalek`            | Acceptable    |
| Signatures        | `ed25519-dalek`                            | Mature        |
| Signatures (PQC)  | `ml-dsa` — **implemented**                 | FIPS 204 final |

The PQC signature crate (`ml-dsa`) is now integrated for ML-DSA-65 after FIPS 204 reached final status.
We do not block the rest of the crypto core on it. Once `ml-dsa` reaches
0.2.x or a viable alternative (`pqcrypto-mldsa`, `libcrux-ml-dsa`)
proves stable, we add it as a follow-up.

## Consequences

**Positive:**

- The entire classical crypto layer rests on mature, audited crates.
- No C toolchain dependency: builds clean on Termux, Linux, macOS.
- We can start implementing immediately; no blocker on PQC signatures.
- `cargo audit` and reproducible builds work uniformly.

**Negative:**

- Until `ml-dsa` is added, NEXUS-Q only offers classical (Ed25519)
  signatures. This is a temporary limitation, documented and tracked.
- `ml-kem 0.3.x` is still pre-1.0; its API may break between minor
  versions. We pin it in `Cargo.toml` and review on each upgrade.
- We accept that PQC signature support will arrive later than the rest.

**Neutral:**

- The choice can be revisited: since we depend on traits (`Signer`,
  `Verifier`), swapping the underlying crate later is a contained change.

## Alternatives revisited in future

- If `ml-dsa 0.2+` does not materialize in a reasonable time, we will
  evaluate `pqcrypto-mldsa` (bindings C) or `libcrux-ml-dsa`
  (formally verified).
- If `ml-kem 0.3` proves insufficient, `pqcrypto-mlkem` is the fallback.

## References

- `docs/CRYPTOGRAPHY.md` — algorithms and parameters
- `docs/ROADMAP.md` §5 — Fase 2 deliverables
- NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA)
- crates.io: RustCrypto project, dalek-cryptography project

---

## Update — 2026-09-25

Revisited the `ml-dsa` decision after implementing the rest of Fase 2.

Findings:

- FIPS 204 was finalized on 2024-08-13; the algorithm itself is
  standardized and believed secure against quantum adversaries.
- The RustCrypto implementation (`ml-dsa`) is at **0.1.1**, released
  2026-06-05. Eighteen releases in eight months.
- The crate is **not independently audited**. Its own README states so.
- Three security advisories in 2026 alone:
  - **CVE-2026-24850** — accepted signatures with duplicate hint
    indices (malleability regression).
  - **CVE-2025-0144** — timing side channel in `Decompose`.
  - Off-by-two in `UseHint` when `r0 == 0`.
  All three are fixed, but they illustrate that the implementation is
  still settling.
- Downstream projects that depend on `ml-dsa` pin exact versions
  (`=0.1.1`) because the API is documented as "still evolving".

**Decision updated: ML-DSA-65 is integrated; SLH-DSA-SHAKE-128f is integrated as the hash-based alternative.**

Revisit conditions:

- `ml-dsa` reaches 0.2.x or higher with a stable API.
- A public audit of the RustCrypto PQC crates is published.
- Fase 15 (Security Engineering) starts, whichever comes first.

When added, ML-DSA will coexist with Ed25519, not replace it. Hybrid
signatures (Ed25519 || ML-DSA) are the intended end state.

Note: `pqcrypto-mldsa` (bindings to PQClean) is being archived upstream
and produces SIGILL on ARM64 Android (as observed with `pqcrypto-mlkem`).
It is not a viable alternative for NEXUS-Q.

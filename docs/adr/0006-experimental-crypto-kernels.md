# ADR 0006 — Experimental cryptographic kernels

- **Status:** Accepted
- **Date:** 2026-11-13
- **Phase:** Crypto Core

## Context

NEXUS-Q uses maintained cryptographic crates for its production
cryptographic implementations. The project also contains the
`nexusq-kernels` crate, which provides project-written low-level
cryptographic reference kernels.

These include:

- Keccak-f[1600].
- SHAKE128 and SHAKE256.
- ML-KEM and ML-DSA number-theoretic transform (NTT) operations.

These kernels create a potential conflict with the golden rule in
`docs/CRYPTOGRAPHY.md`, which states that NEXUS-Q does not invent
cryptography.

The distinction is that these kernels are experimental, correctness-oriented
reference implementations. They are not approved constant-time production
implementations and must not silently replace the maintained upstream
cryptographic implementations.

## Decision

We permit these project-written kernels only as experimental code in
`nexusq-kernels`.

The feature behavior is:

- `nexusq-kernels` enables the kernel crate as a dependency.
- `experimental-kernels` enables the experimental kernel call sites.
- The default build does not enable `experimental-kernels` and therefore
  continues to use the maintained upstream cryptographic implementations
  for the relevant operations.

The existence of these kernels does not establish that they are faster,
more secure, or suitable for production use.

## Security requirements

- Experimental kernels must not be represented as constant-time.
- They must not be used as production cryptographic implementations.
- Correctness tests must cover their supported operations.
- Changes must be reviewed for correctness and security implications.
- The default production cryptographic path must remain on the maintained
  implementations unless a separate decision explicitly approves a change.

## Promotion criteria

Before any experimental kernel can become part of the production
cryptographic path, a separate review and decision must establish:

1. Correctness against the relevant standards and trusted test vectors.
2. Appropriate constant-time and side-channel analysis.
3. Security review of the implementation and its integration.
4. Benchmark evidence supporting the proposed change.
5. Explicit approval through an ADR update or a new ADR.

Passing correctness tests alone is not sufficient for production promotion.

## Consequences

**Positive:**

- Experimental kernel development can continue without silently changing
  the default cryptographic implementation.
- The distinction between maintained upstream implementations and
  project-written reference kernels is documented.
- Future production adoption requires an explicit security decision.

**Negative:**

- The project must maintain additional experimental code and tests.
- Experimental kernels must not be advertised as production-ready or
  constant-time.

**Neutral:**

- The `experimental-kernels` feature remains opt-in.
- The default build continues to use the maintained cryptographic
  implementations.

## References

- `docs/CRYPTOGRAPHY.md` — cryptographic policy and golden rule.
- `docs/adr/0001-crypto-crates.md` — choice of cryptographic crates.
- `crates/nexusq-kernels` — experimental kernel implementations.
- `crates/nexusq-ml-kem/UPSTREAM.md` — ML-KEM local changes.
- `crates/nexusq-ml-dsa/UPSTREAM.md` — ML-DSA local changes.

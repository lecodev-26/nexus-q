# ADR 0002 — Serialization format for the vault body

- **Status:** Accepted
- **Date:** 2026-09-26
- **Phase:** Fase 4 (Vault)

## Context

The vault file (format F-01, `docs/STORAGE.md` §4) stores a structured
body inside an AEAD envelope. That body contains key records, vault
metadata and policy snapshots. We need to choose how to serialize it.

Requirements:

1. Binary and compact: the vault is written and read frequently, and
   is not meant to be human-edited.
2. Self-describing: we must be able to evolve the schema without
   breaking old vaults, and to add fields without prior coordination.
3. Deterministic: the same logical content must produce the same bytes,
   so that checksums and AEAD tags are stable.
4. Well-supported in Rust, on Android/Termux aarch64.
5. Standardized: we do not invent formats.

Candidates considered:

- **CBOR** (`ciborium`) — IETF RFC 8949, binary, self-describing.
- **JSON** (`serde_json`) — universal, but text and bulky.
- **Postcard** — very compact, no_std friendly, but less standardized.
- **Bincode** — fast, but not formally standardized and not
  self-describing in the wire sense.
- Custom — rejected by principle.

## Decision

We adopt **CBOR**, via the `ciborium` crate.

Reasons:

- It is an IETF standard (RFC 8949), not a vendor format.
- It is self-describing: a CBOR decoder can skip unknown fields, which
  is what lets us add fields in future versions without breaking old
  readers.
- It has first-class support for the data types we need: definite-length
  byte strings (for key material), text strings, integers, maps, arrays.
- `ciborium` is pure Rust, actively maintained, and works on the
  platforms NEXUS-Q targets.

For any structure we intend to hash or authenticate, we serialize with
**canonical CBOR** (deterministic field ordering, definite-length
items only) so that the bytes are reproducible.

## Consequences

**Positive:**

- Standard, portable, no vendor lock-in.
- Unknown fields can be skipped, which supports forward-compatible
  schema evolution.
- Binary, compact, no base64 padding overhead.
- Pure Rust dependency tree maintained.

**Negative:**

- Not human-readable; debugging requires a CBOR viewer.
- `ciborium` adds a dependency, though a small and pure-Rust one.
- Canonical encoding requires discipline: we must sort map keys and
  avoid indefinite-length items when we compute hashes.

**Neutral:**

- The choice is contained to the storage layer. Nothing above the
  vault sees CBOR directly; the public API works with Rust types.

## References

- `docs/STORAGE.md` §4 — vault file format (F-01)
- `docs/STORAGE.md` §15 — open questions about serialization
- RFC 8949 — Concise Binary Object Representation (CBOR)
- `ciborium` crate documentation

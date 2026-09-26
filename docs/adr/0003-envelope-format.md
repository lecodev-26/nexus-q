# ADR 0003 — Envelope format (F-02)

- **Status:** Accepted
- **Date:** 2026-09-26
- **Phase:** Fase 5 (Envelope Encryption)

## Context

An envelope is how NEXUS-Q protects **user data**: files, messages,
records. It is the format F-02 in `docs/STORAGE.md` §5.

Design goals:

1. Self-contained: the envelope carries everything needed to decrypt,
   except the key.
2. Authenticated: any modification to the header or the ciphertext is
   detectable before decryption completes.
3. Versioned: the format can evolve without breaking old envelopes.
4. Algorithm-agile: the AEAD used is recorded per envelope.
5. Bound to its key: an envelope cannot be opened with a key it was
   not sealed for.

Two usage modes are anticipated:

- **Vault mode:** the data encryption key (DEK) is wrapped under a key
  in the local vault. Used for encrypting to yourself.
- **Public-key mode:** the DEK is encapsulated with the recipient's
  ML-KEM public key. Used for encrypting to a peer.

Phase 5 implements vault mode first. Public-key mode lands later in
the phase.

## Decision

The envelope is a single CBOR document of this shape:

```

Envelope {
header:       EnvelopeHeader,
wrapped_dek:  bytes,   # DEK wrapped under a vault key, or KEM ciphertext
ciphertext:   bytes,   # AEAD output over the plaintext
}

EnvelopeHeader {
magic:       b"NQX1",           # 4 bytes
version:     u8 = 1,
flags:       u16 = 0,           # reserved
algorithm:   AeadAlgorithm,     # Aes256Gcm | ChaCha20Poly1305
key_id:      KeyId,             # which key protects the DEK
nonce:       [u8; 12],          # AEAD nonce for the data
metadata:    bytes,             # application data, authenticated
}

```

Wire layout: the file is exactly the CBOR encoding of `Envelope`.
Readers parse the whole document before processing, as with the vault.

Authentication:

- The DEK is wrapped with the same routine as key material inside the
  vault (ADR 0002, wrapping module). The AAD is the `key_id`.
- The data is AEAD-encrypted with the DEK. The AAD is the CBOR
  encoding of `EnvelopeHeader`.
- Changing any header field therefore invalidates both the DEK unwrap
  (through the key_id binding, only for some fields) and the data tag
  (through the header AAD, for all fields).

## Consequences

**Positive:**

- Same serialization choice as the vault: one format, one parser,
  one migration story.
- Metadata is authenticated but not encrypted, so callers can inspect
  it (filename, size, timestamp) without decrypting the payload.
- The header carries the algorithm, so old envelopes stay readable
  when defaults change.
- The KeyId binding makes cross-key confusion impossible.

**Negative:**

- CBOR is not human-readable. Debugging requires a CBOR viewer. This
  is the same trade-off already accepted for the vault.
- The envelope is not streamable: the whole document is parsed before
  encryption or decryption. Large files will need a streaming format
  in a later phase. For v1.0, envelopes are intended for files that
  fit comfortably in memory.

**Neutral:**

- The public-key mode reuses the same envelope but changes the
  `wrapped_dek` field into a KEM ciphertext and adds no new fields.
  This keeps one format for two use cases.

## References

- `docs/STORAGE.md` §5 — envelope format specification
- `docs/CRYPTOGRAPHY.md` §4.4 and §5.2 — AEAD and composition rules
- ADR 0002 — CBOR as the serialization format
- RFC 8949 — Concise Binary Object Representation

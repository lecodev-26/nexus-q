# ADR 0004 — Identity model

- **Status:** Accepted
- **Date:** 2026-09-26
- **Phase:** Fase 6 (Identity)

## Context

NEXUS-Q needs a notion of *identity*: an enduring subject that can
sign documents, decrypt data and receive encrypted messages, and whose
cryptographic keys can be rotated without invalidating the subject
itself.

Design constraints:

1. An identity must survive key rotation. Changing the keys must not
   change the identity's public name.
2. An identity must be able to reference several roles: signing,
   encryption and key agreement. Not every identity needs all three.
3. Keys already live in the vault as `KeyRecord`s. Identities should
   reference those keys, not duplicate their material.
4. Verifiers must be able to check a signature using only public
   information: the identity's public key and a signed credential.
5. Identity revocation must be possible without erasing history.

See `docs/ARCHITECTURE.md` §4.3 and `docs/KEY_MANAGEMENT.md`.

## Decision

### Storage

Identities live inside the vault body, alongside keys:

```

VaultBody {
metadata:    VaultMetadata,
keys:        Vec<KeyRecord>,
identities:  Vec<Identity>,
}

```

This keeps every cryptographic asset in one authenticated store and
avoids inventing a second file format.

### Shape

```

Identity {
id:                 IdentityId,
signing_key:        KeyId,             # always present
encryption_key:     Option<KeyId>,     # optional
key_agreement_key:  Option<KeyId>,     # optional
metadata:           IdentityMetadata,
}

IdentityMetadata {
created_at:         Timestamp,
created_by:         String,
label:              Option<String>,
status:             IdentityStatus,
version:            u32,               # bumped on key rotation
revoked_at:         Option<Timestamp>,
revocation_reason:  Option<RevokeReason>,
}

IdentityStatus {
Active,
Rotating,
Revoked,
}

```

`IdentityId` uses the prefix `nqi_` and carries 128 bits of randomness,
mirroring `KeyId` (`nqk_`).

### Operations

All identity operations are methods on `Session`, so they have access
to the vault's KEK:

- `create_identity(algorithm) -> IdentityId`
  * Generates the legacy Ed25519 identity-signing key plus a dedicated
    ML-DSA-65 credential-signing key, activates both, and records the
    identity references.
- `identity_sign(&IdentityId, message) -> Signature`
  * Unwraps the signing key material, signs the message, zeroizes
    the material.
- `identity_verify(&IdentityId, message, &Signature) -> Result<()>`
  * Uses the public half of the signing key. Does not need the KEK.
- `rotate_identity_key(&IdentityId) -> KeyId`
  * Generates replacement identity and credential signing keys, retires
    both previous active keys, preserves their history, and bumps
    `identity.metadata.version`.
- `revoke_identity(&IdentityId, RevokeReason)`
  * Marks the identity revoked. The keys remain in the vault so past
    signatures still verify.

### Key material generation

Identity operations require real Ed25519 keys, not placeholder bytes.
`generate_material` is updated to dispatch per algorithm:

- Ed25519: draw a fresh signing key from the OS RNG, serialize its
  32-byte seed.
- MlKem768: generate a hybrid ML-KEM-768 + X25519 key pair, serialize
  the secret half.
- Aes256Gcm, ChaCha20Poly1305: 32 random bytes, as before.

Two helpers land in the crypto module to support this:

- `crypto::sign::SigningKey::to_bytes() -> [u8; 32]`
- `crypto::kem::hybrid::KeyPair::secret_key_bytes() -> Vec<u8>`

## Consequences

**Positive:**

- One storage location for keys and identities: no two-file
  coordination, no risk of divergence.
- Identity names are stable across key rotation.
- Past signatures remain verifiable after revocation, because the
  public half of retired keys stays accessible through the identity.
- Credentials have a dedicated PQ signing-key slot and history, so new
  credentials use ML-DSA-65 without breaking legacy Ed25519 credentials.

**Negative:**

- `VaultBody` grows a new field; older vaults must be migrated.
  CBOR's self-describing nature makes this a default-field addition,
  not a format break.
- Key material generation becomes algorithm-aware, which couples the
  vault slightly more to the crypto module. This is accepted: the
  alternative — a vault that stores bytes it cannot interpret — is
  worse.

**Neutral:**

- Credentials are not designed here. They will be an additional
  `Vec<Credential>` field in `Identity`, added when their shape is
  decided.

## References

- `docs/ARCHITECTURE.md` §4.3 — identity module
- `docs/KEY_MANAGEMENT.md` — key lifecycle
- `docs/CRYPTOGRAPHY.md` §4.6 — Ed25519
- ADR 0001 — cryptographic crate choices
- ADR 0002 — CBOR as the serialization format

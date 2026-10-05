# Cryptography Guide

NEXUS-Q does not invent cryptographic primitives. The core combines standardized primitives and maintained implementations.

## Current core building blocks

The current documented cryptographic surface includes:

- ML-KEM-768 and ML-KEM-1024 for post-quantum key encapsulation.
- X25519 for hybrid key agreement.
- ML-DSA-65 for post-quantum signatures.
- SLH-DSA-SHAKE-128f for post-quantum signatures.
- Ed25519 for classical signatures.
- AES-256-GCM and ChaCha20-Poly1305 for authenticated encryption.
- SHA-2 and SHA-3 hashing.
- Argon2id and HKDF for key derivation.

The exact algorithm/purpose combinations exposed by a given interface are constrained by that interface.

## Hybrid design

The primary hybrid KEM design combines ML-KEM with X25519. Hybridization is intended to retain security if one component is weakened, subject to the assumptions and composition documented in [Cryptography](../CRYPTOGRAPHY.md).

## What NEXUS-Q does not guarantee

NEXUS-Q does not make a general-purpose device into an HSM, does not defeat a fully compromised operating system, and does not provide physical side-channel protection by itself.

Use [Security Guide](SECURITY.md) and [Threat Model](../THREAT_MODEL.md) before deploying it for sensitive workloads.

# NexusQ HSM integration

`nexusq-hsm` provides an ML-DSA-65 PKCS#11 signer and a quorum-authorized CA key ceremony coordinator. It is designed to be passed directly to `EnrollmentAuthority::new_with_signer`; the enrollment and X.509 layers receive only the public key and a signing callback.

## PKCS#11 signer

- Loads a configured PKCS#11 module and authenticates to a token. Prefer `Pkcs11Provider::connect_by_token_serial` in production; slot-index selection is available for test rigs.
- Generates persistent ML-DSA-65 key pairs with `CKA_TOKEN=true`, `CKA_PRIVATE=true`, `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, and `CKA_SIGN=true` on the private object.
- Requires the PKCS#11 ML-DSA mechanism to produce a hedged signature (`CKH_HEDGE_REQUIRED`). It fails closed if the token does not support the required mechanism; there is no software-key fallback.
- Re-finds token objects by `CKA_ID` in each session. `Pkcs11KeyRef` stores only the opaque object ID, label, token identity and public key. The provider has no private-key export API.
- Keeps the PIN in zeroizing memory and redacts it from `Debug` output. HSM errors returned through the signer interface are sanitized.

The certificate issuer can be wired to this signer without exporting the CA private key:

```rust,ignore
let provider = Pkcs11Provider::connect_by_token_serial(module_path, token_serial, pin)?;
let key_ref = provider.generate_mldsa65_ca_key("nexusq-prod-ca")?;
let signer = Arc::new(Pkcs11MlDsaSigner::new(provider, key_ref)?);
let authority = EnrollmentAuthority::new_with_signer(ca_certificate, signer, policy, first_serial)?;
```

## M-of-N key ceremonies

`CeremonyCoordinator` requires `M` distinct custodian Ed25519 signatures over a domain-separated transcript containing the operation, key label, random nonce, creation time, expiry and (for destruction) the target token key reference. It supports both key generation and key destruction, and rejects unknown custodians, altered transcripts, invalid signatures, duplicate approvals, expired ceremonies and repeat finalization. HSM generation/destruction cannot occur until quorum is reached. Public audit events contain the transcript hash and approval counts, never signatures or private key material.

Use `CeremonyCoordinator` for production operations; direct `Pkcs11Provider` key-management methods are low-level interfaces and do not enforce organizational quorum policy by themselves. This is **quorum authorization for HSM operations**, not threshold cryptographic signing. Use HSM/vendor split knowledge, dual control and native backup policies for the token's own administrative secrets.

## Tests

The default tests exercise the M-of-N state machine with a fake HSM and do not require a PKCS#11 library. See [`docs/recovery.md`](docs/recovery.md) for provisioning, backup/restore and disaster-recovery controls. To run the real-token integration test with SoftHSM2, install SoftHSM2 with ML-DSA-65 support and run:

```bash
./scripts/test-softhsm.sh
```

The integration test generates a non-extractable token key, checks its `Sensitive`/`Extractable` attributes, signs and verifies a message, builds a CA certificate through the external signer callback, and issues a leaf certificate through `EnrollmentAuthority::new_with_signer`. If the SoftHSM build lacks the PKCS#11 ML-DSA mechanism, the test fails rather than silently switching to software.

## Operational limits

Ceremony state and its audit snapshot are currently in memory. Export the audit events to durable tamper-evident storage, and persist ceremony state, token serials, key references and serial allocation before production HA/recovery use. Back up keys only with the HSM vendor's native encrypted backup/restore mechanism; raw private-key export is intentionally unsupported.

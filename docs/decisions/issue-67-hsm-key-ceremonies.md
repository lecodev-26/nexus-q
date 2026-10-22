# Issue #67 — PKCS#11 and M-of-N design

- The new `nexusq-hsm` crate provides a PKCS#11 ML-DSA-65 key provider with non-extractable private-object attributes and no private-key export API.
- `nexusq-x509` now supports an external ML-DSA-65 signature callback; `EnrollmentAuthority::new_with_signer` lets certificate issuance occur inside the HSM without importing the CA private key into process memory.
- `CeremonyCoordinator` requires distinct Ed25519 custodian approvals over a domain-separated transcript before it invokes HSM key generation or key destruction. This is M-of-N authorization, not a threshold-signature implementation.
- A SoftHSM2 integration harness is included. It requires a SoftHSM build that implements PKCS#11 ML-DSA-65 key generation and signing. The development machine currently has no SoftHSM2 utilities/module installed, so the real-token integration test has not been executed here; default unit tests use a fake HSM for the ceremony state machine.
- Ceremony state, audit events and serial allocation remain in memory; durable state, HA, backup and disaster recovery are later concerns. The runbook requires HSM-native encrypted backup/restore and explicit re-binding to a restored token's serial number.

The 4.1.1 release pipeline must publish new dependency crates in order: `nexusq-x509` first, then `nexusq-enrollment` and `nexusq-ocsp`, then `nexusq-hsm` (which has a development integration dependency on `nexusq-enrollment`). A local `cargo package` of `nexusq-hsm` cannot complete until `nexusq-x509` is available in the registry; no publish was attempted.

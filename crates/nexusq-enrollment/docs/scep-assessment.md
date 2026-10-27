# Issue #66 — SCEP assessment

**Historical decision for the 4.1.1 enrollment profile: do not enable SCEP.** Keep ACME, EST and the CMPv2 P10CR/PBM profile as the supported enrollment paths in this iteration.

## Why

- SCEP deployments commonly depend on a shared `challengePassword`, CMS SignedData conventions, legacy interoperability modes, and implementations that may negotiate SHA-1. Those semantics need a separate compatibility/security profile rather than being silently accepted by the PKCS#10 validator used by ACME/EST/CMP.
- The current policy engine intentionally permits only ML-DSA-65 signed CSRs, DNS SAN identities authorized by suffix policy, and a constrained leaf-certificate extension set. SCEP clients often expect RSA/ECDSA key profiles and different attribute behavior.
- Reusing the current endpoint without SCEP-specific authentication, transaction replay handling, CMS interoperability tests and a migration policy would create a protocol-confusion and downgrade risk.

## Reconsider SCEP when

A concrete device-management use case names the target client/vendor and its required algorithms. The follow-up should define a dedicated `/scep` adapter with separate authentication and replay protection, explicitly configured legacy algorithms, and interoperability tests against that target. SCEP must not bypass `EnrollmentAuthority::enroll_csr`, identity authorization, rate limits or audit recording.

No SCEP route is registered by `nexusq-enrollment` in this iteration.

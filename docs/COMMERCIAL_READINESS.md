# NEXUS-Q Commercial Readiness & Due Diligence

This document is the evidence-oriented companion to GitHub Issue #21. It
separates **implemented evidence** from **remaining gates** so commercial
materials never turn engineering intent into an unsupported security claim.

## Current status

**Status: Engineering due-diligence package in progress. Not commercially
released.**

The repository contains a substantial engineering baseline, security model,
cryptographic documentation, CI gates, benchmark evidence and release tooling.
Several commercial gates necessarily remain open, especially independent
external security review, final public release acceptance, legal/compliance review,
commercial terms and customer validation.

## Evidence already present

| Area | Evidence | Status |
|---|---|---|
| Threat model | `docs/THREAT_MODEL.md` | Present |
| Security model | `docs/SECURITY_MODEL.md` | Present |
| Cryptography claims | `docs/CRYPTOGRAPHY.md` | Present; claims constrained to evidence |
| Audit logging | `docs/OBSERVABILITY.md`, audit implementation | Present |
| Security CI | `.github/workflows/security-ci.yml` | Present |
| V2 security/fuzz gate | `.github/workflows/v2-security-fuzz.yml` | Present |
| Correctness/interoperability | V2-08 workflow and docs | Present |
| Benchmark baseline | `docs/V2_BENCHMARK_BASELINE.md` | Present |
| V2 profiling | `docs/V2_PROFILE.md` | Present |
| Backend strategy | `docs/V2_BACKEND_STRATEGY.md` | Present |
| Dependency metadata | CI `cargo metadata` artifact | Present |
| License | MIT + Apache-2.0 files and Cargo metadata | Present |
| Security disclosure | `SECURITY.md` | Present |
| Contribution policy | `CONTRIBUTING.md` | Present |
| Change history | `CHANGELOG.md` | Present |
| Code ownership | `.github/CODEOWNERS` | Present |

## Explicit commercial blockers

These are not to be silently marked complete:

1. Independent external security audit.
2. Final public V2 release acceptance after post-merge CI.
3. Reproducible release artifacts, checksums, SBOM and provenance as a
   published release package.
4. Final supported-platform matrix based on tested release artifacts.
5. Legal/compliance review appropriate to the intended market, including
   export-control/dual-use questions.
6. Final commercial licensing, support/SLA and pricing decisions.
7. Customer/design-partner validation and credible reference evidence.
8. Final IP/provenance and third-party license review appropriate for a
   commercial transaction.

## Claims policy

Until the blockers above are satisfied, public material must use terms such as
"engineering baseline", "development", "measured evidence" and "internal
security gates" where appropriate. It must not imply:

- independent security-audit completion;
- FIPS validation or certification;
- Common Criteria certification;
- formal verification;
- finalized standards conformance where only a draft construction is used;
- hardware-backed isolation where only the software provider is available;
- production support/SLA commitments that have not been approved.

## Due-diligence data-room structure

The eventual release/commercial package should preserve these evidence groups:

```text
due-diligence/
  source-provenance/
  licenses-and-notices/
  dependencies-and-sbom/
  security/
    internal-audit/
    external-audit/
    vulnerability-history/
  benchmarks/
  architecture-and-threat-model/
  release-provenance/
  supported-platforms/
  legal-and-commercial/
  pilots-and-customer-validation/
```

Do not place production secrets, private keys, customer confidential data or
unredacted vulnerability details in the public repository.

## Release sequence

Commercial readiness does not bypass the engineering roadmap. The intended
sequence is:

1. finish V2 engineering gates;
2. complete release candidate and final audit/review work;
3. run the real release CI and fix failures until green;
4. publish only the explicitly supported crates/bindings/artifacts;
5. publish signed/checksummed release evidence and documentation;
6. complete legal/commercial/customer gates;
7. make the final commercial/public claims from the evidence actually produced.

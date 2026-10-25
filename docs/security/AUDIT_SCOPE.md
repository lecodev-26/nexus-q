# Proposed independent security audit scope

- **Status:** Draft for agreement with an independent auditor; no audit is implied or claimed
- **Prepared:** 2026-10-25
- **Candidate baseline:** Current repository `main` after the maintainer resolves the `4.1.1` source-identity discrepancy
- **Primary references:** [`THREAT_MODEL.md`](../THREAT_MODEL.md), [`SECURITY_MODEL.md`](../SECURITY_MODEL.md), [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md), [`ARCHITECTURE.md`](../ARCHITECTURE.md), and [`RELEASE_INTEGRITY_INVENTORY.md`](../RELEASE_INTEGRITY_INVENTORY.md)

## Purpose

Define a reviewable starting point for an independent security assessment of NEXUS-Q's default RustCrypto implementation, key/data handling, policy enforcement, protocol-facing components, and release supply chain. The auditor should confirm or amend this scope before work begins. CI, fuzzing, dependency scanning, and this document are not substitutes for independent review.

## Baseline and prerequisites

1. The maintainer and auditor must agree on an immutable commit and record its full commit ID, repository URL, lockfiles, toolchain, build instructions, and artifact digests.
2. Resolve the discrepancy between the bare `4.1.1` tag, `v4.1.1`, current `main`, and already-published release provenance before treating any one of them as the audited release. See the [release integrity inventory](../RELEASE_INTEGRITY_INVENTORY.md).
3. Record any build that cannot be reproduced, unavailable evidence, unsupported targets, and excluded code explicitly in the engagement report.
4. The independent auditor must have freedom to expand scope based on findings and dependency review.

## Proposed in-scope areas

### 1. Core cryptography and key lifecycle

- ML-KEM-768 / ML-KEM-1024, ML-DSA-65, SLH-DSA-SHAKE-128f, X25519 hybrid use, Ed25519 legacy verification, AES-256-GCM, ChaCha20-Poly1305, hashing/KDF/password-hardening and algorithm-binding rules as implemented in the agreed baseline.
- Key generation, import/export, wrapping, derivation, storage, rotation, revocation, zeroization, error handling, and secret lifetime.
- Envelope and vault serialization, authenticated metadata, nonce handling, tamper rejection, downgrade resistance, and compatibility boundaries.
- Constant-time claims and side-channel-sensitive code paths, with claims checked against actual code and dependencies rather than documentation alone.

### 2. Authorization, sessions, and audit records

- Policy evaluation, key purpose/capability checks, session/vault state transitions, authentication/authorization separation, fail-closed behavior, and security-sensitive API validation.
- Audit event coverage, integrity authentication, append-only assumptions, log failure behavior, and avoidance of secrets in logs.

### 3. Network and PKI-related components

- `nexusq-server` public request handling and authorization boundaries.
- Enrollment and X.509/OCSP paths, CSR/certificate validation, policy enforcement, and malformed-input handling.
- TSA/CMS token construction and validation assumptions, including the documented `RUSTSEC-2023-0071` dependency exception.
- HA and PKI-cluster coordination only to the extent included in the agreed deployment and threat model; clarify distributed-systems guarantees separately from cryptographic guarantees.

### 4. Interfaces and integration boundaries

- Rust public API, CLI, C ABI, and SDK glue for unsafe code, memory ownership, input validation, error propagation, and consistent policy enforcement.
- Python and other language bindings only where included in the engagement; list exact bindings, targets, and package versions in the final report.
- HSM/hardware-provider abstractions and attestation assumptions. Vendor firmware, physical tamper resistance, and specific hardware certification require separate access and scope.

### 5. Build and release supply chain

- Cargo manifests and lockfiles, dependency provenance and advisory policy, build scripts, native compilation, CI workflow permissions, artifact identity, checksums, SBOM completeness, provenance/attestation verification, and release immutability controls.
- Compare release artifacts with the agreed source commit and build instructions. Registry package availability must not be treated as source-commit provenance.
- Review the documented temporary exception for `RUSTSEC-2023-0071` and any other active dependency exceptions.

## Explicit exclusions unless separately agreed

- A compromised OS/kernel, privileged local attacker, physical side-channel laboratory assessment, cold-boot resistance, and hardware-vendor firmware internals.
- Formal verification, mathematical proof of implementation correctness, certification, FIPS 140-3 validation, Common Criteria, and compliance attestations.
- Full denial-of-service resilience, production deployment configuration, external identity providers, cloud-provider security, and customer-specific operational practices.
- Experimental native ML-KEM/ML-DSA backend and its kernels are **not included in the primary assurance claim**. They should be assessed as a separate optional workstream if the auditor has the required expertise and the project intends to make security claims about them.
- Every published ecosystem package is not automatically covered by an audit of the Rust workspace. The engagement must explicitly name the bindings, generated artifacts, release commit, and package versions covered.

An exclusion is a scope boundary, not a statement that the excluded area is safe.

## Known review items to disclose

- The `4.1.1` Git refs and existing public release provenance do not currently identify one consistent source snapshot; do not begin an audit of a release artifact until the exact baseline is selected.
- `RUSTSEC-2023-0071` is temporarily ignored by `cargo audit` and `cargo deny` under a documented decision record. The advisory is not considered fixed; see [`ADR 0005`](../adr/0005-rsa-cms-rustsec-2023-0071.md).
- The published SBOM currently describes workspace packages rather than a complete third-party dependency inventory; produce a dependency-complete SBOM for the selected baseline.
- The native backend is experimental and opt-in; default RustCrypto paths and optional native paths must not be conflated in the report.
- No independent external audit, certification, FIPS validation, or production-readiness assessment is claimed as of this draft.

## Expected auditor deliverables

1. Scope confirmation, methodology, exclusions, and agreed immutable baseline.
2. Findings with severity rationale, affected commit/component, exploitability assumptions, and reproducible evidence.
3. Explicit review of cryptographic design and implementation, key lifecycle, parser/input boundaries, dependency exceptions, and supply-chain controls.
4. Retest results for fixes and a residual-risk statement for accepted or unresolved findings.
5. A public-summary version approved for publication, with sensitive exploit details handled under the engagement's disclosure policy.

## Acceptance criteria for closing the audit item

- The agreed commit and relevant artifacts are immutable and independently identifiable.
- Scope and exclusions are signed off by both project maintainer and auditor.
- Findings and fixes have traceable evidence; unresolved findings are explicitly recorded and dispositioned.
- Any public statement matches the actual audited commit, components, and artifacts. A clean CI run or completed fuzz campaign alone does not satisfy these criteria.

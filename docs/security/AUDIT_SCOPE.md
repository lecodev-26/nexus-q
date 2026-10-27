# NEXUS-Q v4.1.2 Audit Scope

Status: Accepted. Independent external audit pending.

## Purpose

Define the source snapshot, claims, exclusions, and evidence expected for an independent security review of the v4.1.2 candidate. This document is scope-setting only; it is not an audit report or a claim that the release is production-ready.

## In scope

- The exact reviewed v4.1.2 candidate commit and its dependency lockfiles.
- The default RustCrypto code paths for key handling, vault/container formats, enrollment, TSA, X.509, server entry points, and public SDK interfaces.
- The 13 Rust source files reviewed for the candidate, including the let-chain and CAS changes; final behavioral confirmation remains subject to KAT and CI on the exact candidate commit.
- Workspace MSRV declaration and locked dependency resolution.
- Release automation that builds artifacts, validates artifact inventory, generates `SHA256SUMS`, CycloneDX SBOM, `release-manifest.json`, and build attestation.
- The documented exception for `RUSTSEC-2023-0071` and the configured dependency-audit controls.
- Public security claims, release notes, and traceability from the source commit to produced artifacts.

## Out of scope unless separately agreed

- A claim of FIPS 140-3 validation, Common Criteria certification, or formal verification.
- A claim of production readiness or completion of an independent external audit.
- Hardware isolation or assurance for a TPM, HSM, Secure Element, compromised operating system, hypervisor, or physical attacker beyond explicitly tested integrations.
- The experimental native backend as a production cryptographic provider; it remains opt-in and outside default-provider claims. Any audit of that backend requires a separately agreed scope.
- Guarantees about all language-registry packages unless each artifact is linked to the exact source commit by verifiable evidence.
- Side-channel guarantees beyond the specific analysis and tests agreed with the auditor.

## Required candidate evidence

- Exact commit and clean source inventory.
- Reproducible commands and results for formatting, locked checks, tests, KAT/interoperability checks, and MSRV (`Rust 1.88.0`, `cargo check --workspace --locked`).
- Dependency-audit output with the `RUSTSEC-2023-0071` exception visible and justified; do not mark the advisory fixed.
- Complete final asset list, checksums, SBOM, machine-readable release manifest, and build attestation bound to the artifact digests.
- Explicit record of skipped, unavailable, or unverified checks; no inferred success.

## Public status language

Use exactly: “Audit-Ready Release. No production-readiness claim, no FIPS validation, external audit pending.” Do not imply that the independent audit has finished or that a certification has been obtained.

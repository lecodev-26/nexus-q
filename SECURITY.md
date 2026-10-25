# Security Policy

## Supported security line

NEXUS-Q v4.1.1 is published, but its source identity is **not yet reconciled**. The bare `4.1.1` tag resolves to `5dd564daab9da1c071b8b134894ea7c4eba95d09`; `v4.1.1` and `main` resolve to `84992f91589ae56957fdd5b2a727fcaef7f108a1`. Existing release provenance and attested release binaries identify `5dd564d`, not the current `v4.1.1` target. A GitHub repository ruleset now prevents updates and deletion of the `v4.1.1` tag, but this does not make the existing GitHub Release assets immutable; GitHub's release metadata reports `immutable=false`. Treat the published version as a known provenance discrepancy until a maintainer-approved reconciliation plan is completed. Do not assume that packages carrying version `4.1.1` were built from one common commit.

The current workspace declares Rust 1.88; the source snapshot associated with the existing release attestation declares Rust 1.85. Exact builds with those minimum toolchains have not been verified as part of this work. No independent external audit has been completed. NEXUS-Q does **not** claim production readiness, FIPS validation, Common Criteria certification, or formal verification. The native ML-KEM/ML-DSA backend remains experimental and outside the primary assurance claim; RustCrypto remains the default production path.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's
GitHub **Security Advisories** / private vulnerability reporting mechanism when
available. Do not disclose an unpatched vulnerability in a public issue.

Include, when safe to provide:

- affected commit, tag, or package version;
- affected component/API;
- reproduction or proof of concept;
- expected and observed behavior;
- security impact and prerequisites;
- any suggested mitigation.

Do not include production secrets, private keys, passwords, customer data, or
other sensitive material in a report.

If private reporting is temporarily unavailable, open a minimal public issue
requesting a private contact channel; do not publish exploit details there.

## Response targets

These are engineering targets, not contractual SLAs:

| Severity | Acknowledge | Triage target | Fix/release target |
|---|---:|---:|---:|
| Critical | 2 business days | 5 business days | 14 calendar days |
| High | 3 business days | 10 business days | 30 calendar days |
| Medium | 5 business days | 15 business days | Next appropriate release |
| Low | 10 business days | 30 business days | Planned maintenance |

Targets may be extended when coordinated disclosure, upstream fixes, or
reproduction requires additional time. The reason and current status should be
recorded internally.

## Security gates

Changes are expected to preserve the repository security gates, including
formatting, linting, tests, dependency auditing/denial checks, secret scanning,
and the configured fuzzing gates. Main-branch fuzz soak is configured for
45 minutes per designated parser target; V2 development PRs use the shorter
5-minute smoke gate.

## Scope and limitations

NEXUS-Q is software. The software backend does not provide hardware isolation
from a compromised OS, kernel, hypervisor, or physical attacker. TPM/HSM/Secure
Element support is an abstraction/future integration point unless a concrete
provider is explicitly documented and tested.

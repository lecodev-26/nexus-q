# Security Policy

## Supported security line

The `main` branch is the engineering baseline. Until an explicitly published
release exists, security fixes are developed against the active release branch
and backported only when maintainers judge the change safe and applicable.

NEXUS-Q does **not** claim FIPS validation, Common Criteria certification,
formal verification, or completion of an independent external security audit
unless a corresponding public evidence package is linked from this repository.

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

# Security Policy

## Supported security line

V3 is the engineering line integrated into `main`; V4 kernel work is in the separate active PR #46 targeting `nexusqv4`. GitHub engineering releases do not imply publication to crates.io, PyPI, or other SDK registries. Security fixes should be developed against the active branch for the affected line and backported only when maintainers judge the change safe and applicable.

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

Changes are expected to preserve the repository security gates, including formatting, linting, tests, dependency auditing/denial checks, secret scanning, and the configured fuzzing gates. The authoritative workflow is `.github/workflows/ci.yml`, with separate SDK/benchmark workflows. Iterative `v4/**` PR runs intentionally omit the long fuzz soaks; those remain a later release/security gate and must not be claimed as passed for a V4 commit unless evidence for the relevant source SHA is linked. Workflow scopes and durations can change, so use the workflow and its exact run artifacts rather than treating historical V1/V2 timings as current policy.

## Scope and limitations

NEXUS-Q is software. The software backend does not provide hardware isolation
from a compromised OS, kernel, hypervisor, or physical attacker. TPM/HSM/Secure
Element support is an abstraction/future integration point unless a concrete
provider is explicitly documented and tested.

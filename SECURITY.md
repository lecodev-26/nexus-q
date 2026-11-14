# Security Policy

## Supported security line

**Policy approved and last reviewed: 2026-11-14.** Only the latest published stable NEXUS-Q release is supported for security fixes. As of this review, that release is **v4.1.2** (the current v4.1.x release). Earlier patches and development snapshots are not independently supported. The v4.2.x line is not supported until a v4.2.x stable release is published; when a newer stable release is published, it becomes the supported release line.

Security fixes are developed against the active engineering baseline. Backports to an older release are considered case by case, based on security impact, compatibility, and the risk of introducing regressions; there is no automatic backport commitment. Any maintenance of an older line must be explicitly announced by the maintainers.

The current release's public status is: “Audit-Ready Release. No production-readiness claim, no FIPS validation, external audit pending.” Release evidence is provided separately and must be checked against the exact tagged commit and artifact digests. Registry availability alone is not proof that every ecosystem package was built from the same Git commit.

NEXUS-Q does **not** claim FIPS validation, Common Criteria certification, formal verification, or completion of an independent external security audit unless corresponding public evidence is linked from this repository.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's
[GitHub Security Advisories form](https://github.com/lecodev-26/nexus-q/security/advisories/new)
(private vulnerability reporting). Private vulnerability reporting is enabled
in the repository settings; GitHub sign-in is required to access the form. Do
**not** create a public issue containing
vulnerability details, exploit steps, proof-of-concept code, affected secrets,
or information that would help an attacker reproduce the issue.

The repository's issue tracker links to this private reporting channel. If you
cannot access the private form, create only a minimal public issue titled
"Request for a private security contact" and state that you need a secure
reporting channel. Do not include technical details, attachments, logs, or
proof-of-concept material in that public issue. Maintainers will follow up with
a private channel.

Include the following information **only in the private report**, and only
when safe to provide:

- affected commit, tag, or package version;
- affected component/API;
- reproduction or proof of concept;
- expected and observed behavior;
- security impact and prerequisites;
- any suggested mitigation.

Do not include production secrets, private keys, passwords, customer data, or
other sensitive material in a report.

Never use a public issue, pull request, discussion, or comment to disclose
unpatched vulnerability details. The public issue fallback is for requesting a
private contact channel only.

## Response targets

These are engineering targets, not contractual SLAs:

| Severity | Acknowledge receipt | Initial triage and substantive reporter update | Fix/release target |
|---|---:|---:|---:|
| Critical | 2 business days | 5 business days | 14 calendar days |
| High | 3 business days | 10 business days | 30 calendar days |
| Medium | 5 business days | 15 business days | Next appropriate release |
| Low | 10 business days | 30 business days | Planned maintenance |

Acknowledgement confirms receipt and gives the reporter a point of contact.
The initial substantive update communicates the current severity assessment,
known impact, next steps, or any information still needed; if triage is not
complete, it provides a status update by the target above. These are engineering
targets, not guarantees. Targets may be extended when coordinated disclosure,
upstream fixes, or reproduction requires additional time. The reason and
current status should be recorded internally.

## Security gates

Changes are expected to preserve the repository security gates, including
formatting, linting, tests, dependency auditing/denial checks, secret scanning,
and the configured fuzzing gates. Main-branch fuzz soak is configured for
45 minutes per designated parser target; V2 development PRs use the shorter
5-minute smoke gate.

## Static analysis

The repository runs CodeQL SAST for Rust, C/C++, Go, Python, and GitHub Actions. The versioned workflow, query scope, exclusions, local reproduction guidance, and false-positive triage process are documented in [`docs/security/STATIC_ANALYSIS.md`](docs/security/STATIC_ANALYSIS.md). A clean scan is not a guarantee that the code is vulnerability-free.

## Scope and limitations

NEXUS-Q is software. The software backend does not provide hardware isolation
from a compromised OS, kernel, hypervisor, or physical attacker. TPM/HSM/Secure
Element support is an abstraction/future integration point unless a concrete
provider is explicitly documented and tested.

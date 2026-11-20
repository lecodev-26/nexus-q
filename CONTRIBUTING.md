# Contributing to NEXUS-Q

Thank you for helping build NEXUS-Q. Contributions of code, tests, documentation, security research, reviews, reproducible bug reports, and design feedback are welcome. You do not need to contact the maintainer before opening a focused, non-sensitive Pull Request.

NEXUS-Q is security-sensitive software. Correctness, reviewability, interoperability, and evidence take priority over speed or code volume. Read this guide together with [AGENT.md](AGENT.md), the detailed repository map and working guide for human contributors and AI coding agents.

## 1. Find a useful contribution

- Browse [open issues](https://github.com/lecodev-26/nexus-q/issues) for known work. Check labels and recent activity before starting.
- Browse [GitHub Discussions](https://github.com/lecodev-26/nexus-q/discussions) for design proposals, questions, and technical debates.
- Search existing PRs and code to avoid duplicating work.
- Small documentation fixes, focused tests, and self-contained bug fixes can generally go straight to a PR.
- For broad changes, new cryptographic behavior, public API or format changes, or significant compatibility/security implications, open a Discussion or issue first.

You are welcome to pick up an existing issue or propose a new improvement. If no issue exists, explain the problem and scope in the PR; no maintainer assignment is required unless the issue explicitly says otherwise.

## 2. Read the project guidance

Start with:
1. [AGENT.md](AGENT.md) — repository map, task-specific reading, development workflow, and AI-agent instructions.
2. [README.md](README.md) — project scope, maturity, supported paths, and current status.
3. [SECURITY.md](SECURITY.md) — vulnerability disclosure policy.
4. [Architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [security model](docs/SECURITY_MODEL.md), and [cryptography rules](docs/CRYPTOGRAPHY.md).
5. [CI pipeline](docs/ci-pipeline.md) — automatic checks and specialized workflows.

Read task-specific docs and ADRs for the affected crate, API, storage format, SDK, or workflow. Check status banners and dates because some reports are historical.

## 3. Security and engineering principles

- Do not invent cryptography or replace established primitives without documented design and review.
- Do not casually change algorithm parameters, randomness requirements, nonce rules, key sizes, domain separation, serialization, or wire/storage formats.
- Preserve constant-time assumptions, zeroization, key lifetimes, and fail-closed error handling.
- Use OS-backed cryptographically secure randomness for production secrets. Never reuse seeds, nonces, or one-time secret inputs.
- Keep unsafe Rust within justified low-level boundaries and document each unsafe block's safety invariants.
- Preserve workspace and upstream lint policies, licenses, notices, pinned revisions, and source provenance.
- Never commit credentials, private keys, production vaults, customer data, unredacted logs, fuzz crash artifacts, or generated secrets.
- Do not claim code is audited, production-ready, certified, or constant-time without evidence.

If you discover a possible vulnerability, stop public disclosure and follow [SECURITY.md](SECURITY.md). Never put exploit steps, proof-of-concept code, affected secrets, or sensitive reproduction details in public issues, discussions, PRs, or comments.

## 4. Set up and make a focused change

Clone with submodules:

    git clone --recurse-submodules https://github.com/lecodev-26/nexus-q.git
    cd nexus-q

The current main workspace uses Rust 1.88 or newer (edition 2024). Install rustfmt and Clippy for Rust work. Standalone crates, native components, fuzz targets, and SDKs may need additional toolchains; see [AGENT.md](AGENT.md).

Create a branch from an up-to-date main:

    git switch main
    git pull --ff-only origin main
    git switch -c type/short-description

Keep changes focused and reviewable. Add regression tests for behavior changes, including relevant negative/error paths. Update docs when APIs, behavior, formats, configuration, or operational expectations change.

## 5. Validate and report honestly

The primary Fast CI checks for the root Rust workspace are:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --locked
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo test --workspace --locked

Run relevant checks locally where your environment supports them. Standalone native components, SDKs, fuzz targets, dependency audits, and release gates have separate workflows. See [docs/ci-pipeline.md](docs/ci-pipeline.md).

Do not claim a command passed if it was not run. List exact commands and results, distinguishing local checks from GitHub Actions. CI validates configured checks only; it is not an external security audit, certification, or proof of production readiness.

## 6. Open a Pull Request — no private coordination required

1. Push your topic branch to your fork or repository.
2. Open a PR targeting main. GitHub loads the [PR template](.github/PULL_REQUEST_TEMPLATE.md).
3. Explain the problem, motivation, implementation, affected components, security/correctness impact, compatibility, validation evidence, and limitations.
4. Link a related issue or Discussion. If none exists, describe the context in the PR.
5. Wait for GitHub Actions to finish for the latest PR HEAD. If a check fails, inspect logs, fix the cause, push an update, and let Actions run again.
6. Respond to review feedback constructively.
7. A maintainer reviews and merges when ready. Contributors must not merge their own PR unless explicitly authorized.

You do not need to send the maintainer a separate message to announce your PR. Opening a complete PR is the correct way to submit work.

## 7. PR checklist

- [ ] One clear purpose and descriptive title.
- [ ] Related issue/discussion linked, or context explained.
- [ ] Tests added for behavior changes and actual validation documented.
- [ ] Security impact, compatibility, migration, and limitations described.
- [ ] Documentation updated where needed.
- [ ] No secrets, private data, generated build output, or unrelated changes.
- [ ] Licenses, attribution, and upstream provenance preserved.
- [ ] Actions results correspond to the latest commit when checks have completed.

For cryptographic changes, discuss algorithms and parameters, randomness, serialization, constant-time assumptions, zeroization, key lifetimes, interoperability, and test-vector provenance.

## 8. AI-assisted contributions

AI tools are welcome, provided the human contributor remains responsible for the submitted work.

- Start by asking the agent to read [AGENT.md](AGENT.md) and this document completely.
- Require it to inspect the branch, working tree, relevant code, tests, and docs before proposing edits.
- Ask for a concise plan before broad or security-sensitive changes.
- Review generated code and tests yourself. Verify cryptographic claims against standards and authoritative sources.
- Never provide agents with production secrets, private keys, vault contents, or sensitive customer data.
- Never let an agent invent test results, security assurances, audit status, or CI evidence.
- Agents must not push, open PRs, merge, approve, publish, or release unless explicitly authorized.

Suggested starting prompt:

> Read AGENT.md and CONTRIBUTING.md completely. Inspect the current branch, working tree, and recent history. Summarize project constraints and task-specific documents before proposing a focused plan. Do not modify or publish anything until authorized. For any change, add appropriate regression tests, run relevant checks, inspect the complete diff, and report exact commands and results. Never claim an unrun check or unsupported security assurance.

## 9. Community standards

Participation follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). For usage help and routing, see [SUPPORT.md](SUPPORT.md). Report suspected vulnerabilities only through the private process in [SECURITY.md](SECURITY.md).

## 10. Licensing

By contributing, you confirm that you have the right to submit the work under the repository's applicable MIT OR Apache-2.0 licensing terms. Keep third-party provenance and license notices intact.

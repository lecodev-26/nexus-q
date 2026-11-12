# NEXUS-Q — Agent and Contributor Guide

> The entry point for human contributors and AI coding agents. Read this before inspecting, changing, testing, reviewing, or proposing work in this repository. It explains the project, security boundaries, repository layout, contribution workflow, and validation expectations.
>
> The checked-out source, current GitHub Actions workflows, and focused documents linked below are authoritative. If this guide conflicts with current source or workflow configuration, report the discrepancy and follow the current implementation.

## 1. Project identity

NEXUS-Q is an open-source post-quantum cryptographic security engine written primarily in Rust. It provides reusable cryptographic and security building blocks for protecting data, keys, and identities. The repository contains a Rust workspace, command-line and server interfaces, C/Python interfaces, language bindings, optional integrations, benchmark tooling, security research material, and extensive documentation.

The project is library-first: application interfaces should call the core rather than reimplement cryptographic behavior. The core combines standardized cryptographic algorithms and maintained cryptographic libraries with vault/key lifecycle management, envelope encryption, policy enforcement, and tamper-evident audit logging.

Project links:
- Repository: https://github.com/lecodev-26/nexus-q
- Website: https://nexus-q.link
- Discussions: https://github.com/lecodev-26/nexus-q/discussions
- Issues: https://github.com/lecodev-26/nexus-q/issues
- Pull requests: https://github.com/lecodev-26/nexus-q/pulls
- Actions: https://github.com/lecodev-26/nexus-q/actions
- Security policy: https://github.com/lecodev-26/nexus-q/blob/main/SECURITY.md

### Current engineering baseline

The current workspace metadata declares Rust edition 2024, minimum Rust 1.88, workspace package version 4.1.2, and MIT OR Apache-2.0 licensing. The default cryptographic implementation path is RustCrypto. The optional native ML-KEM/ML-DSA backend is experimental and explicitly opt-in through Cargo features.

Do not infer that every package, binding, published artifact, target platform, or registry package has identical maturity or release provenance. Check package-specific documentation and release evidence before making compatibility or provenance claims.

### Security and maturity statement — read this

NEXUS-Q is security-sensitive software. The repository does **not** claim production readiness, an independent external security audit, FIPS validation, Common Criteria certification, or formal verification. Automated tests, CI success, fuzzing, benchmark results, package publication, and security documentation are useful evidence, but none is equivalent to an independent audit or certification.

The native backend is experimental and opt-in. RustCrypto remains the default path. Scalar/reference kernels must not be described as externally audited unless verifiable independent audit evidence is added. Do not silently enable experimental backends in default builds, CLI, server, or SDKs.

Hardware-provider abstractions do not by themselves provide hardware isolation. Do not claim TPM, HSM, Secure Element, enclave, or hardware-backed guarantees unless a concrete provider is implemented, supported, tested, and documented for the specific deployment.

The software backend cannot protect a running process from an attacker who controls its OS, kernel, hypervisor, privileged account, build pipeline, or physical environment. Read the threat model before making security claims.

## 2. How AI agents must operate

When an AI agent is given this repository:

1. Read this file first, then inspect the current Git status, branch, recent commits, and relevant source before proposing edits.
2. Read applicable architecture, threat model, security model, cryptography, storage, API, and package documentation before touching those areas.
3. Determine the narrowest correct scope. Prefer one issue or one coherent concern per change. Avoid unrelated cleanup and broad refactors.
4. Treat source code, tests, documentation, CI workflows, vendored upstream code, and release evidence as distinct sources of truth. Never invent implementation status, test results, audit status, or compatibility.
5. Preserve existing public APIs, wire formats, serialized data, key derivation, cryptographic parameters, and compatibility unless the task explicitly requires a reviewed migration.
6. Never invent cryptographic primitives or protocols. Prefer established, maintained implementations and documented standards.
7. Never weaken security checks, lint rules, test assertions, fuzzing, dependency policy, or CI gates merely to make a change pass.
8. Inspect the final diff and report exactly what changed, what was and was not validated, known limitations, and any migration or security impact.
9. Do not claim a command passed unless it was actually run and its exit status was observed. Distinguish local checks from GitHub Actions results.
10. Do not publish, push, merge, approve, release, rotate credentials, modify repository settings, or perform other externally visible/destructive actions without explicit authorization from the human directing the agent. Follow that person's requested branch/PR workflow.
11. Do not expose secrets in prompts, logs, diffs, test fixtures, issue comments, discussions, or PR descriptions. Never ask a user to paste private keys, passwords, tokens, vault contents, or production credentials.
12. If requirements are ambiguous or a security decision changes trust assumptions, stop and ask a focused question rather than guessing.

### Safe working sequence

- Establish repository state: git status, current branch, HEAD SHA, and upstream relationship.
- Read relevant source and tests; search for all call sites and serialized-format consumers.
- Write a short plan for non-trivial work.
- Implement the smallest coherent change.
- Add or update regression tests and documentation as appropriate.
- Run formatting, targeted tests, and relevant broader checks locally when the environment permits.
- Inspect git diff, git diff --check, and git status.
- Commit with a clear descriptive message.
- Open or update a PR unless the maintainer explicitly requests another route.
- Wait for GitHub Actions and review the exact commit SHA tested.
- Do not merge based only on local results or a green run for a different SHA.

This sequence is guidance, not permission to perform remote actions. The human maintainer controls publication and merge decisions.

## 3. Repository map

| Path | Responsibility |
|---|---|
| crates/nexusq-core | Core library: cryptography, vault, keys, identity, policy, storage, audit, and provider abstractions |
| crates/nexusq-kernels | Kernel interfaces and scalar/reference kernel implementations |
| crates/nexusq-ml-kem | ML-KEM algorithm crate and integration |
| crates/nexusq-ml-dsa | ML-DSA algorithm crate and integration |
| crates/nexusq-cli | Command-line application |
| crates/nexusq-server | HTTP server/service |
| crates/nexusq | Aggregate/public Rust crate |
| crates/nexusq-c and crates/nexusq-py | C ABI and Python integration |
| Other crates under crates/ | PKI, OCSP, enrollment, HSM, TSA, HA, cluster, and administration components; inspect each manifest and docs for exact scope |
| bindings/ | Language SDKs and bindings, including Go, PHP, Ruby, Java, Kotlin, Swift, .NET, Dart, and TypeScript/Node.js material |
| vendor/ | Vendored or forked upstream code; preserve provenance, licenses, notices, and upstream security/lint policy |
| arena/ | PQC Benchmark Arena, pinned adapters, registries, schemas, and benchmark methodology |
| fuzz/ | cargo-fuzz package and fuzz targets |
| security-audit/ | AI-assisted audit tooling and its validation tests |
| docs/ and docs/user/ | Architecture, security, cryptography, API, operations, release, performance, decision records, and user guides |
| .github/workflows/ | GitHub Actions CI, security, fuzz, SDK, benchmark, and release workflows |
| .github/scripts/ | CI validation and repository automation scripts |
| deploy/, scripts/, examples/ | Packaging, release, engineering scripts, and usage examples |
| artifact-archive/ | Historical evidence and archived artifacts; check dates and status before treating as current |

Workspace membership and excluded standalone manifests are declared in the root Cargo.toml. Some directories, including the native backend, benchmark runners, and vendored crates, are intentionally outside the main workspace and have their own manifests and validation commands. Do not assume cargo test --workspace covers them.

## 4. Essential reading by task

Start with:
- README.md — overview, capabilities, current status, installation, and navigation.
- CONTRIBUTING.md — contributor expectations.
- SECURITY.md — private vulnerability reporting and security policy.
- docs/ARCHITECTURE.md — system structure and component boundaries.
- docs/THREAT_MODEL.md — adversaries, assumptions, and out-of-scope threats.
- docs/SECURITY_MODEL.md — security controls and limitations.
- docs/CRYPTOGRAPHY.md — cryptographic algorithms and intended use.
- docs/ci-pipeline.md — CI workflow overview.

Task-specific reading:

| Change area | Read these first |
|---|---|
| Vault, backup, storage, audit log | docs/STORAGE.md, docs/KEY_MANAGEMENT.md, docs/security/AUDIT_LOG_KEY_LIFECYCLE.md, relevant ADRs |
| Cryptographic algorithms and protocol formats | docs/CRYPTOGRAPHY.md, docs/THREAT_MODEL.md, docs/adr/, algorithm crate docs and tests |
| Policy and authorization | docs/POLICY.md, docs/OPERATION_CONTROL.md, relevant core modules and tests |
| Server and API | docs/SERVER.md, docs/API.md, docs/DEPLOYMENT.md |
| Native backend and kernels | docs/performance/NATIVE_BACKEND.md, docs/performance/NATIVE_BACKEND_FEATURE.md, docs/performance/NATIVE_BACKEND_PRODUCTION_WIRING.md, docs/security/issue-71-kernel-integration.md |
| SDKs and language bindings | docs/user/SDK.md, docs/C_SDK.md, relevant binding README/build files and sdk-ci workflow |
| Fuzzing | docs/V2_SECURITY_FUZZING.md, fuzz/Cargo.toml, .github/workflows/fuzz-soak.yml |
| Benchmarks | BENCHMARKS.md, arena/README.md, docs/performance/CORRECTNESS_AND_SECURITY.md and relevant benchmark workflow |
| Release and package provenance | docs/V4_RELEASE.md, docs/user/PUBLISHING.md, .github/workflows/v4-release.yml and package publication workflows |
| AI audit tooling | docs/security/AI_SECURITY_AUDIT.md, security-audit/README.md, security-audit/tests/ and ai-audit-validation workflow |

Some documents are historical or archived. Check status banners and dates; do not treat historical plans, closed issue checklists, or old run results as the current roadmap or live CI status.

## 5. Security-critical engineering rules

### Cryptography and protocol behavior

- Do not implement custom cryptography when a maintained, reviewed primitive is available.
- Do not change algorithm parameters, domain separation, KDF parameters, nonce rules, key sizes, encodings, serialization, or protocol/wire formats casually.
- Any format or protocol change requires explicit compatibility and migration analysis, including old data, old clients, downgrade behavior, and recovery behavior.
- Preserve constant-time assumptions and use constant-time comparison primitives where required.
- Preserve zeroization and secret-lifetime guarantees. Avoid unnecessary secret copies, debug output, formatting, or serialization.
- Use OS-backed cryptographically secure randomness. Never use predictable or reused randomness for production keys, nonces, seeds, or ephemeral secrets.
- Deterministic randomness is acceptable only in explicitly controlled test/vector contexts where the API and test make that boundary clear.
- Do not weaken error handling or turn authentication/integrity failures into success or silent fallback.
- Keep parsing bounded and fail closed on malformed, truncated, inconsistent, or unauthenticated data.
- Add negative tests for tampering, invalid lengths, wrong keys, invalid states, and interrupted persistence where relevant.
- Preserve interoperability with published standards and official test vectors. Do not modify expected vectors to match a broken implementation.

### Rust and unsafe code

- Follow the workspace MSRV, edition, formatting, lint, and dependency conventions.
- Keep unsafe code out of safe crates. Where unsafe is permitted in specialized low-level crates, every unsafe block must have a precise SAFETY comment explaining the invariants and why the operation is sound.
- Preserve crate-level and workspace lint policies, including vendored upstream lint policy when restoring or modifying vendored manifests.
- Do not silence a lint globally or broadly to conceal a defect. Any narrowly scoped allow must be justified and documented.
- Avoid panics in public/library paths for untrusted input. Return typed errors consistent with surrounding APIs.
- Avoid adding dependencies without a clear need; check license, maintenance, MSRV, feature, and security implications.

### Data, secrets, and repository hygiene

Never commit access tokens, passwords, API keys, signing keys, private keys, certificates containing private material, production vaults, real customer data, unredacted logs, crash dumps, fuzz crash artifacts, benchmark outputs containing sensitive information, generated build output, or local machine configuration unless explicitly required and documented.

Preserve license files, copyright notices, attribution, pinned upstream revisions, and source provenance. For vendored code, make the smallest possible change and clearly identify upstream versus project-owned modifications.

### Security vulnerability disclosure

Never publish vulnerability details, exploit steps, proof-of-concept code, affected secrets, or reproduction instructions in public issues, PRs, discussions, or comments. Use the private reporting process in SECURITY.md and the GitHub Security Advisories form. If private reporting is unavailable, follow the minimal public contact-request procedure described there; do not include technical details.

## 6. Local development setup

### Requirements

For the root Rust workspace: Git, Rust 1.88 or newer (edition 2024), rustfmt and Clippy components, and network access to fetch dependencies on the first build. A C toolchain may be needed by dependencies or specific native/SDK tasks.

The repository has a Git submodule for Wycheproof test data. Clone with submodules when possible:

    git clone --recurse-submodules https://github.com/lecodev-26/nexus-q.git
    cd nexus-q

If already cloned:

    git submodule update --init --recursive

Install/update the required Rust components:

    rustup toolchain install 1.88.0 --component rustfmt --component clippy
    rustup override set 1.88.0

A newer compatible stable toolchain is possible for local development, but CI's primary fast workflow pins Rust 1.88.0. When diagnosing CI differences, reproduce with the pinned toolchain first.

### Baseline workspace checks

Run from the repository root:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --locked
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo test --workspace --locked

These are the primary Fast CI checks. The workspace test command does not automatically test every excluded standalone crate, every SDK, every fuzz target, every benchmark adapter, or every release workflow.

For a quick patch hygiene check:

    git diff --check

For a focused crate, prefer a narrow command first, for example:

    cargo test -p nexusq-core --locked
    cargo test -p nexusq-cli --locked
    cargo test -p nexusq-server --locked
    cargo test -p nexusq-ml-kem --locked
    cargo test -p nexusq-ml-dsa --locked

For a focused integration test, use the exact target name discovered in that crate's tests directory:

    cargo test -p nexusq-core --test <integration_test_name> --locked

Do not guess test target names; inspect the repository first.

### Optional native backend checks

The native ML-KEM/ML-DSA backend is experimental and excluded from the default workspace path. It must remain opt-in. Relevant core integration checks include:

    cargo check -p nexusq-core --features native-backend --locked
    cargo test -p nexusq-core --features native-backend --locked
    cargo test -p nexusq-core --features native-backend-portable --locked
    cargo clippy -p nexusq-core --features native-backend --all-targets --locked -- -D warnings

The standalone native backend has its own manifest and workflow. Consult .github/workflows/native-backend-gate.yml and crate documentation before running it. These commands can require native build dependencies and are not substitutes for the default RustCrypto checks.

### Fuzzing

Fuzz targets live in fuzz/. They are not covered by cargo test --workspace. Install cargo-fuzz and inspect the fuzz workflow before running a campaign:

    cargo install cargo-fuzz --locked
    cargo fuzz list
    cargo fuzz build

A bounded local smoke run can be performed for a specific target, for example:

    cargo fuzz run vault_parse -- -max_total_time=60 -timeout=30

Other targets include envelope_parse and backup_import; inspect fuzz/fuzz_targets/ for the full list. Longer soak campaigns are expensive and are handled by the dedicated GitHub Actions workflow. Preserve and report any discovered crash input; do not silently delete or modify a reproducer.

### Dependency and security audits

The manual dependency workflow is .github/workflows/audit-ci.yml. It audits the root lockfile and standalone native/benchmark lockfiles, then runs cargo-deny. The commands include:

    cargo audit --file Cargo.lock
    cargo audit --file crates/nexusq-native-backend/Cargo.lock
    cargo audit --file arena/runners/nexusq-native/Cargo.lock
    cargo deny check

Install cargo-audit and cargo-deny only when needed. Read .cargo/audit.toml and deny.toml before interpreting known exceptions. Never suppress an advisory or change policy merely to obtain a green result; document and escalate any exception.

### Documentation and SDK validation

Rust documentation can be checked with:

    cargo doc --workspace --no-deps --locked

SDKs have language-specific toolchains and validation. Consult docs/user/SDK.md, docs/C_SDK.md, the relevant binding directory, and .github/workflows/sdk-ci.yml. Do not claim an SDK is validated merely because the Rust workspace passes.

The AI security audit helper has its own lightweight tests and dependencies. Consult security-audit/README.md and .github/workflows/ai-audit-validation.yml before changing it.

## 7. GitHub Actions and validation

### Fast CI

The primary workflow is .github/workflows/ci.yml, named **NEXUS-Q Fast CI**. It runs on pushes to main, pull requests targeting main (opened, synchronized, reopened, or marked ready for review), and manual workflow dispatch.

It checks out submodules and runs, using Rust 1.88.0:
1. cargo fmt --all -- --check
2. cargo check --workspace --all-targets --locked
3. cargo clippy --workspace --all-targets --locked -- -D warnings
4. cargo test --workspace --locked

A green Fast CI run proves those configured jobs passed for the exact checked-out revision. It does not prove an independent security audit, full fuzz campaign, all SDKs, all platforms, release reproducibility, production readiness, or certification.

### Other important workflows

Workflow names and triggers can evolve. Inspect current YAML before relying on a workflow's behavior.

| Workflow file | Purpose |
|---|---|
| ci.yml | Main fast Rust workspace checks and tests |
| audit-ci.yml | Manually dispatched Rust dependency audit and cargo-deny |
| security-ci.yml | Manually dispatched repository data contracts and secret scanning |
| fuzz-soak.yml | Long sequential fuzz campaigns |
| correctness-interoperability.yml | Additional correctness, vector, and interoperability checks |
| native-backend-gate.yml | Experimental native backend validation, differential tests, and benchmark gates |
| native-assembly-ci.yml | Specialized kernel/assembly checks, unsafe policy, docs, and formatting |
| sdk-ci.yml | Language SDK and native runtime checks |
| native-runtime.yml | Cross-platform C ABI runtime artifacts and smoke tests |
| ai-audit-validation.yml | Lightweight tests for AI audit tooling |
| ai-security-audit.yml | Manually dispatched AI-assisted static security audit |
| benchmarks.yml, hybrid-benchmark.yml, pqc-arena.yml | Benchmark and Arena workflows |
| v4-release.yml | Release evidence, platform gates, packaging, provenance, and publication controls |
| publish-packages.yml, publish-nuget.yml | Explicit package publication workflows |

Do not confuse a manually dispatched workflow with a check that runs on every PR. Do not claim a manual security, fuzz, benchmark, SDK, or release workflow passed unless it was actually run and its exact run/revision was checked.

### Required PR validation discipline

For a normal contribution:
1. Push the proposed commit to a topic branch and open a PR against main.
2. Ensure the PR describes scope, motivation, security impact, tests, compatibility, and limitations.
3. Wait for the required GitHub Actions checks to finish.
4. Inspect failed logs and fix the root cause; do not weaken checks.
5. Confirm the successful run corresponds to the latest PR HEAD SHA.
6. Request review and respond to review comments.
7. Merge only through the maintainer-approved process.

A contributor should not merge their own PR unless explicitly authorized by repository maintainers. Never approve a PR on behalf of another reviewer. Never force-push or rewrite shared history without explicit authorization.

## 8. How to make a high-quality contribution

### Before coding

- Search existing issues, discussions, PRs, and code to avoid duplicating work.
- Confirm the problem and expected behavior.
- Identify affected crates, public APIs, data formats, bindings, and documentation.
- Read the threat model and relevant ADRs for security-sensitive work.
- Define acceptance criteria and regression tests.

### During implementation

- Keep changes focused and reviewable.
- Follow existing naming, error, module, and test conventions.
- Add regression tests that fail before the fix and pass after it.
- Test both success and failure paths.
- Consider malformed input, adversarial input, concurrency, crash/interruption, persistence, recovery, and backward compatibility where relevant.
- Update user and developer documentation when behavior, API, configuration, or operational guidance changes.
- Keep generated artifacts out of commits unless the task specifically requires them.
- Preserve exact upstream test vectors and cite their source.

### PR description checklist

A useful PR should state:
- Problem and motivation.
- Summary of implementation and files/components affected.
- Security impact and assumptions.
- Whether algorithms, parameters, key lifetimes, serialization, wire formats, or public APIs changed.
- Tests and checks actually executed, with exact commands.
- GitHub Actions evidence, when available.
- Compatibility, migration, and rollback considerations.
- Known limitations and deferred work.
- Related issue/discussion links.

For cryptographic changes, explicitly describe constant-time considerations, zeroization, randomness, error handling, interoperability, and test-vector provenance where relevant.

### Commit messages

Use concise, imperative, descriptive commit messages. The repository commonly uses conventional-style prefixes such as:

    fix(vault): reject invalid audit persistence paths
    feat(audit): support versioned key rotation
    test(crypto): add official interoperability vectors
    docs(security): clarify assurance limitations

Do not claim a fix is security-audited in a commit message unless independent audit evidence exists.

## 9. Documentation and communication standards

- Use precise, evidence-backed language.
- Distinguish implemented, experimental, planned, unsupported, and historical capabilities.
- Include dates and exact commit/run identifiers for time-sensitive evidence.
- Do not copy old benchmark figures or CI statuses as if they were current.
- Keep README, package docs, release notes, and security docs consistent.
- Public discussions are appropriate for design proposals and non-sensitive technical debate.
- Vulnerability details belong only in the private reporting channel described by SECURITY.md.
- Be welcoming to first-time contributors; explain context and link to relevant design documents.

## 10. Before declaring work complete

The agent or contributor should be able to answer:
- What exact user problem does this change solve?
- Why is this the correct layer and smallest safe change?
- Which APIs, formats, dependencies, targets, and consumers are affected?
- What threat-model assumptions or security properties are relevant?
- Which regression tests were added or updated?
- Which commands were run locally, and what were their actual results?
- Which GitHub Actions run validated the exact final SHA?
- Were any specialized workflows required but not run?
- Are docs, changelog, examples, and migration notes updated where needed?
- Is the final diff focused, clean, and free of secrets or generated artifacts?
- What limitations remain?

If any answer is unknown, say so explicitly. Do not turn an unknown into an assurance claim.

## 11. Quick start for a new AI-assisted contributor

A practical first prompt to an AI agent is:

> Read AGENT.md and CONTRIBUTING.md completely. Inspect the current branch, git status, and recent history. Then read the threat model and the documentation relevant to the task. Do not modify files until you have summarized the project constraints and proposed a focused plan. Do not publish, push, merge, approve, or release anything without my explicit permission. For any change, add appropriate regression tests, run the relevant local checks, inspect the complete diff, and report exact commands and results. Use GitHub Actions as the authoritative CI evidence for the exact commit SHA.

For a new contributor without a specific task, start with GitHub Discussions, look for issues labeled for contribution, ask maintainers before taking on broad security-sensitive work, and submit a focused PR with evidence.

---

**Maintainer note:** keep this file synchronized with the actual source tree, Cargo workspace, security policy, contribution guide, and GitHub Actions workflows. When changing CI commands, MSRV, security posture, repository structure, or contribution policy, update this guide in the same change.


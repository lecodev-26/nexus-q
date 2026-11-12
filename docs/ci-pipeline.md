# NEXUS-Q GitHub Actions architecture

This document describes the workflow configuration in .github/workflows/. Workflow triggers are authoritative: a workflow listed below does not run on every Pull Request unless its YAML explicitly configures that trigger.

## Automatic Fast CI

.github/workflows/ci.yml is named **NEXUS-Q Fast CI**. It runs on pushes to main, pull requests targeting main (opened, synchronized, reopened, or marked ready for review), and manual workflow_dispatch with an optional ref or commit SHA.

The workflow checks out recursive submodules and uses Rust 1.88.0 with rustfmt and Clippy. Its workspace job runs:

1. cargo fmt --all -- --check
2. cargo check --workspace --all-targets --locked
3. cargo clippy --workspace --all-targets --locked -- -D warnings
4. cargo test --workspace --locked

A successful run is evidence that these configured steps passed for the exact checked-out revision. It does not establish that every standalone crate, SDK, fuzz target, platform, release path, or manually dispatched workflow passed. It is not an independent security audit, certification, or production-readiness assessment.

## Specialized workflows and their triggers

These workflows are separate from Fast CI. The trigger column reflects the workflow YAML currently in this repository; inspect that YAML for exact inputs, matrices, and job-level conditions before dispatching or relying on a result.

| Workflow | Trigger | Purpose / boundary |
|---|---|---|
| audit-ci.yml | Manual dispatch | Dependency audit and cargo-deny checks. |
| security-ci.yml | Manual dispatch | Repository security/data-contract checks, secret scanning, and related security validation. |
| correctness-interoperability.yml | Manual dispatch | Additional correctness, interoperability, and official/vendored vector suites. |
| fuzz-soak.yml | Manual dispatch | Longer sequential fuzz campaigns; not equivalent to compiling the fuzz harness. |
| native-backend-gate.yml | Manual dispatch | Experimental native backend provenance, differential/constant-time checks, and performance gates. |
| native-backend-aa-control.yml | Manual dispatch | Informational A/A control for hosted-runner benchmark noise. |
| native-assembly-ci.yml | Manual dispatch | Specialized kernel/assembly, formatting, documentation, and unsafe-boundary checks. |
| sdk-ci.yml | Manual dispatch or reusable workflow call | Language SDK and native runtime checks. |
| sdk-runtime.yml | Manual dispatch or reusable workflow call | Default RustCrypto C ABI runtime artifacts; not automatically published. |
| native-runtime.yml | Manual dispatch or reusable workflow call | Experimental native-provider runtime artifacts; separate from default SDK runtime and not automatically published. |
| pqc-arena.yml | Manual dispatch | PQC Arena registry, runner, schema, and benchmark evidence validation. |
| benchmarks.yml | Manual dispatch | Cross-platform core benchmark runs and reproducibility metadata. |
| hybrid-benchmark.yml | Manual dispatch | Production hybrid ML-KEM-768/X25519 benchmark evidence. |
| ai-audit-validation.yml | Push to main or PR, limited to security-audit/workflow paths | Lightweight validation for AI-assisted audit tooling; this is a separate automatic check when its path filters match. |
| ai-security-audit.yml | Manual dispatch | AI-assisted static security audit workflow, with selectable audit profile. |
| publish-packages.yml | Manual dispatch | Explicitly confirmed crates.io, PyPI, and RubyGems publication from an already released annotated version tag. |
| publish-nuget.yml | Manual dispatch | Explicitly confirmed NuGet publication using GitHub Actions OIDC and validated RustCrypto runtime artifacts. |
| v4-release.yml | Manual dispatch | Release evidence build/dry-run; actual GitHub Release publication requires a separate explicit input and exact annotated version tag. |

The specialized manual workflows do not automatically run on every PR. Reusable workflows run only when called by another workflow. A workflow being present does not mean it has run for a given PR or commit.

## PR validation discipline

1. Open a focused PR against main and describe scope, motivation, security/correctness impact, compatibility, tests, and limitations.
2. Wait for required Actions checks to finish.
3. Confirm the successful run corresponds to the latest PR HEAD SHA, not an earlier push.
4. Inspect failed logs and fix the root cause; do not weaken checks.
5. Respond to review comments and push follow-up commits as needed.
6. A maintainer merges when ready. Contributors must not merge their own PR unless explicitly authorized.

Do not claim a manual security, fuzz, benchmark, SDK, or release workflow passed unless it was dispatched and its run and exact revision were checked.

## Publication and security boundaries

- No registry publication is triggered by an ordinary push, PR, or successful Fast CI run.
- Publishing workflows default to a no-op unless the operator explicitly sets the confirmation input.
- Package publication is restricted by configured release/tag and provenance checks; inspect the current workflow before preparing a release.
- NuGet uses OIDC; do not add a long-lived NuGet API key to repository secrets.
- The ordinary SDK runtime remains RustCrypto. Experimental native-provider artifacts are separate and must not be substituted into ordinary SDK packages.
- A green CI or benchmark result is evidence only for the checks actually run. It is not proof of FIPS validation, production readiness, or a completed independent audit.

The workflows are intentionally separated so expensive jobs run only when requested and results remain attributable to the exact selected ref.

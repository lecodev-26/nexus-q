# Rust dependency trust and unsafe-code inventory

NEXUS-Q uses complementary tools for different supply-chain questions:

- `cargo-deny` enforces advisories, licenses, duplicate-version exceptions, crate bans, and allowed dependency sources through `deny.toml`. The dedicated policy workflow checks the root workspace and the separately locked native workspaces on every pull request to `main` and every push to `main`. See [Cargo dependency policy](CARGO_DENY.md).
- `cargo-vet` records which third-party Rust crates have been reviewed against explicit trust criteria. Its version-controlled store is `supply-chain/`.
- `cargo-geiger` produces a machine-readable inventory of `unsafe` usage in the workspace dependency graph. The report is uploaded as a GitHub Actions artifact.

These tools are not interchangeable. A clean dependency-policy check does not mean every crate has been audited, and an `unsafe` count is not a vulnerability verdict.

## Cargo-vet baseline and review policy

The initial `supply-chain/config.toml` contains exact-version exemptions for the registry dependencies in the current workspace graph. These entries are a bootstrap backlog, **not completed audits or an endorsement of those crates**. The notes on every baseline entry say so, and the entries remain eligible for `cargo vet suggest`.

When adding or updating a third-party dependency:

1. Review the dependency's source, maintainership, release history, security posture, and transitive impact.
2. Run `cargo vet suggest` and inspect the package/version that needs review.
3. After an actual source review, record the appropriate result with `cargo vet certify` and retain the generated audit record in `supply-chain/audits.toml`.
4. If a full audit is not yet possible, keep a narrow exact-version exemption with a concrete rationale and follow-up owner/context. Do not describe an exemption as an audit.
5. Add a trusted audit import only after reviewing the publisher's identity, audit criteria, scope, and update process. Record that trust decision in `supply-chain/config.toml`.
6. Revisit exemptions when dependencies change and reduce the backlog over time. Never run `cargo vet regenerate exemptions` merely to make a failing check green without reviewing the resulting trust decisions.

`cargo vet check` is a required check in the supply-chain workflow. A newly introduced registry dependency without an audit or an explicit reviewed exemption must be addressed before merge. The initial baseline intentionally preserves the current dependency graph so existing packages can be reviewed incrementally rather than falsely marked as audited.

## Cargo-geiger inventory

The GitHub Actions workflow pins `cargo-geiger` to 0.14.0. Because the root manifest is a virtual workspace and cargo-geiger accepts one package root per invocation, the workflow enumerates every root-workspace package with Cargo metadata, adds the separately locked `crates/nexusq-native-backend`, `arena/runners/nexusq`, and `arena/runners/nexusq-native` workspaces, scans each package with all features and targets enabled, and combines the per-package JSON reports into `cargo-geiger.json`. Intermediate per-package report filenames include their workspace-relative path to avoid collisions. Each successful run uploads that aggregate as an artifact named with the validated commit SHA; artifacts are retained for 30 days. The workflow is triggered by project Rust source changes as well as manifest, lockfile, and policy changes.

Treat the report as an inventory and triage aid only:

- `unsafe` usage is not automatically a vulnerability; sound abstractions can require carefully constrained unsafe code.
- A low or zero count does not prove memory safety, soundness, or absence of vulnerabilities.
- Review findings in context, prioritizing project-maintained unsafe blocks, FFI boundaries, cryptographic code, and dependencies with broad exposure.
- Compare reports across commits and investigate material changes; do not fail CI merely because a crate reports unsafe usage.

The aggregate covers the root Cargo workspace and the separately locked native backend and Arena runner workspaces. The vendored C and assembly sources in the experimental native backend are not interpreted by cargo-geiger; they remain an explicit manual-review boundary documented in `docs/security/NATIVE_BACKEND_AUDIT_SCOPE.md`.

## Tool versions and ownership

- `cargo-vet`: 0.10.3
- `cargo-geiger`: 0.14.0
- `cargo-deny`: 0.18.4 (see [Cargo dependency policy](CARGO_DENY.md))
- Policy source: `supply-chain/config.toml`, `supply-chain/audits.toml`, and `deny.toml`
- Automation: `.github/workflows/cargo-deny.yml` and `.github/workflows/supply-chain-audit.yml`

Review changes to the trust store as security-sensitive policy changes. Keep rationale, exact crate versions, audit criteria, and any imported audit source visible in the pull request.

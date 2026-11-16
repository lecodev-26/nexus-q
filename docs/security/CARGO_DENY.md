# Cargo dependency policy

NEXUS-Q uses `cargo-deny` 0.19.9 as a CI gate. The version-controlled policy is `deny.toml`; `.github/workflows/cargo-deny.yml` runs it on every pull request targeting `main`, every push to `main`, and manual dispatch.

## Enforced policy

- **Advisories:** all current advisories fail except the narrowly documented `RUSTSEC-2023-0071` exception. Its security rationale and reassessment triggers are recorded in [ADR 0005](../adr/0005-rustsec-2023-0071-rsa-advisory.md).
- **Licenses:** only the SPDX identifiers explicitly listed in `deny.toml` are accepted.
- **Crate bans:** `native-tls` and `hyper-tls` are prohibited so HTTP clients use rustls. OpenSSL is not blanket-banned because the current `josekit` dependency requires it; the policy permits that direct edge only and rejects other consumers. Its native binding is permitted only through `openssl`.
- **Duplicates:** new duplicate crate versions fail. The exact-version `skip` entries document the incompatible upstream version lines already present in the checked-in dependency graph. Each exception includes its current consumer and a migration/removal rationale; do not add broad crate-name-only skips.
- **Sources:** crates.io is the only allowed registry and Git-sourced dependencies are denied.

## Checked dependency graphs

The workflow checks all three committed lockfile contexts:

1. The root Cargo workspace (`Cargo.toml` / `Cargo.lock`).
2. The excluded native backend (`crates/nexusq-native-backend/Cargo.toml` / `Cargo.lock`).
3. The excluded native Arena runner (`arena/runners/nexusq-native/Cargo.toml` / `Cargo.lock`).

The separate `arena/runners/nexusq` workspace has no independent lockfile and is not a separate locked dependency graph in this gate. The vendored crates are source inputs, not independent application workspaces in the policy workflow.

## Regression proof

The workflow runs a second `cargo-deny` invocation with a fixture policy that deliberately bans `serde`, which is present in the root workspace graph. The step succeeds only when cargo-deny exits unsuccessfully and its diagnostics identify the banned `serde` crate. This verifies that the gate is capable of rejecting a controlled policy violation rather than merely completing successfully on the current graph.

## Updating exceptions

When a duplicate is reported, inspect its reverse dependency paths and first try to align dependency versions. Add an exact-version skip only when incompatible upstream constraints make immediate convergence impractical; explain the consumer, incompatibility, and removal trigger in the same entry. When introducing a Git dependency, obtain an explicit security review and update the source policy only with a documented justification. Do not weaken a ban or license rule merely to make CI green.

# Cargo vulnerability auditing

NEXUS-Q runs `cargo-audit` as a blocking GitHub Actions check on every pull request targeting `main` and every push to `main`. The workflow also supports manual dispatch. It audits each committed lockfile independently:

- `Cargo.lock` for the root workspace.
- `crates/nexusq-native-backend/Cargo.lock` for the excluded native backend workspace.
- `arena/runners/nexusq-native/Cargo.lock` for the excluded native runner workspace.

The workflow pins `cargo-audit` to **0.23.0** and uses the RustSec Advisory Database with fetching enabled and stale databases disallowed. Each audit reads the committed lockfile via `--file`; it does not regenerate or update dependency lockfiles. A failure in any lockfile audit blocks the workflow.

## Advisory exceptions

The policy currently retains one narrowly scoped exception: `RUSTSEC-2023-0071`, documented in [ADR 0005](../adr/0005-rustsec-2023-0071-rsa-advisory.md). It is not considered fixed. `.cargo/audit.toml` contains the tool's ignore list, and `.cargo/audit-exceptions.toml` contains the owner, rationale, and expiry metadata for every allowed exception. The workflow runs `.github/scripts/check-cargo-audit-exceptions.py` before auditing and fails if:

- an ignored advisory has no matching metadata (or metadata has no corresponding ignore entry);
- an advisory is listed more than once;
- an exception omits its owner, rationale, or expiry date; or
- the expiry date is today or in the past.

An exception must be proposed in a reviewed PR and include the exact RustSec ID, a responsible owner, a concrete impact/risk rationale, and an expiry date in `YYYY-MM-DD` format. Keep the exception narrow and temporary; prefer upgrading or removing the affected dependency. The current `RUSTSEC-2023-0071` exception is owned by `lecodev-26` and expires on 2026-12-16; its technical rationale and reassessment triggers remain in ADR 0005. The owner must remove or explicitly renew the exception through a reviewed change before expiry. CI automatically rejects it at expiry. Never add an advisory ID to the ignore list without its matching metadata.

## Negative policy check

The workflow audits `.github/fixtures/cargo-audit/vulnerable.lock`, which deliberately pins `time 0.1.45`. RustSec advisory `RUSTSEC-2020-0071` identifies this release line as affected. The check passes only when `cargo-audit` exits unsuccessfully and its output contains that exact advisory ID; an unrelated failure (for example, an unavailable advisory database) does not count as a successful negative test.

The fixture is isolated from production lockfiles and is never used to resolve or build project dependencies.

## Scope and limitations

`cargo-audit` identifies known RustSec advisories in the committed lockfiles. It does not prove exploitability, reachability, absence of vulnerabilities, or security of vendored C/assembly code. It complements rather than replaces `cargo-deny`, source review, fuzzing, Miri, and independent security assessment.

The workflow creates a stable check named **NEXUS-Q Cargo Audit / cargo-audit (all lockfiles)**. Repository branch protection or rulesets must require this check for merges; workflow YAML alone cannot change repository merge rules.

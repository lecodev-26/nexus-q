# Rust workspace test coverage

NEXUS-Q measures line coverage with `cargo-llvm-cov` in GitHub Actions. The dedicated `NEXUS-Q Coverage` workflow runs weekly and on manual dispatch, keeping this resource-intensive report separate from the automatic Fast CI path. Each run publishes an HTML per-file report and its LCOV source data as a 30-day artifact; the workflow summary links directly to that artifact. The workflow summary links to the uploaded artifact.

## Reproduce a report

Use the repository-pinned Rust toolchain and install the LLVM tools component:

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.9.1 --locked
cargo llvm-cov --workspace --all-targets --locked --lcov --output-path coverage/lcov.info
cargo llvm-cov report --html --output-dir coverage/html
```

Open `coverage/html/index.html` to inspect per-file coverage. The CI workflow runs this against the same workspace and default feature selection as the ordinary workspace test suite; it does not imply coverage for separately managed workspaces or SDK projects.

## Measurement scope

The versioned gate measures executable Rust lines in production source files under `crates/*/src/`. It reports the workspace aggregate and separate critical-module aggregates:

- Vault: `crates/nexusq-core/src/vault/`
- Policy engine: `crates/nexusq-core/src/policy/`
- Authenticated audit log: `crates/nexusq-core/src/storage/audit_event.rs`, `audit_log.rs`, and `audit_segment.rs`

The LCOV parser uses executable-line records (`DA`) and counts a line as covered when its execution count is greater than zero. Module percentages are computed from the union of the files in each configured path set, not by averaging file percentages.

## Exclusions

The aggregate intentionally excludes test, benchmark, and example directories; fuzz targets; vendored dependencies; the standalone native-backend and Arena workspaces; SDK projects outside the root Rust workspace; build-script output outside the crate source tree; and documentation. The report is not a claim that these surfaces are covered. Changes to this scope require an explicit documentation update and review.

## Threshold policy

The version-controlled `.github/coverage-thresholds.json` defines the global and critical-module minimums enforced by `.github/scripts/check-coverage.py`. The initial measured baseline was 88.51% globally, 96.25% for vault, 99.74% for policy, and 94.64% for the authenticated audit log. The initial minimums are deliberately set just below those measured values (88.0%, 95.0%, 99.0%, and 94.0%, respectively) to prevent regressions without claiming unattained coverage. The global threshold and each critical-module threshold are independent: a high workspace aggregate cannot hide a low vault, policy, or audit-log result. A missing module in the report fails closed. Thresholds must be raised deliberately as coverage improves; do not lower a threshold merely to make a run green.

Coverage is a regression signal. It does not prove assertion quality, cryptographic correctness, constant-time behavior, memory safety, or security certification.

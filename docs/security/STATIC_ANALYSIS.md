# Static application security testing (SAST)

NEXUS-Q uses GitHub CodeQL as its versioned SAST engine. CodeQL was selected
instead of adding both CodeQL and Semgrep because GitHub code scanning supports
the repository's principal implementation languages (Rust, C/C++, Go, and
Python) and GitHub Actions workflows, and publishes findings in the repository's
Security/code-scanning interface. For public repositories on GitHub.com,
GitHub documents code scanning as available without requiring a paid GitHub
Code Security entitlement. This workflow does not depend on Semgrep's hosted
platform or an API token.

The workflow is defined in `.github/workflows/codeql.yml`; its query and path
policy is `.github/codeql/codeql-config.yml`. The CodeQL Action is pinned to the
full v4 commit `33d7b85da1a04171e211befe2c739303b9a4c066`, and checkout is pinned
to `11bd71901bbe5b1630ceea73d27597364c9af683` (v4.2.2). The workflow sets
`tools: linked`, so the CodeQL CLI bundle comes from the pinned Action revision
instead of resolving a floating recommended bundle. Update pins only in a
reviewed change, and record the release/version beside each pin. See the
[GitHub CodeQL code-scanning documentation](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-code-scanning)
for supported languages and public-repository availability.

## Coverage and execution

The workflow analyzes these languages independently so a failure is attributable
to one language:

| Language | CodeQL mode | Scope |
| --- | --- | --- |
| Rust | `none` | Rust source without invoking a full Cargo build |
| C/C++ | `none` | Native backend and C/C++ SDK source |
| Go | `manual` | Go SDK and CIRCL adapter modules, built with Go 1.25.0 |
| Python | interpreted | Repository Python tooling and scripts |
| GitHub Actions | interpreted | Workflow definitions |

Analysis runs for pull requests targeting `main`, pushes to `main`, a weekly
schedule, and manual dispatch. Pull requests from forks are still analyzed,
but SARIF upload is disabled for those runs because GitHub does not grant
write access to fork-originated `pull_request` workflows. Their analysis job
status remains visible in Actions. Results from trusted repository events are
uploaded to GitHub code scanning.

The `security-extended` query suite is enabled. The configuration excludes
third-party vendored source (`**/vendor/**`), build output (`**/target/**`),
and generated source (`**/generated/**`). These exclusions are intentional:
NEXUS-Q does not own upstream vendor code, build products, or generated output.
Project-maintained code, tests, scripts, SDKs, and workflow files remain in
scope. Do not add broad exclusions for cryptographic or native-code directories.

## Reproducing a scan locally

Use the CodeQL CLI bundle corresponding to the pinned CodeQL Action release
and the official CodeQL CLI documentation for installation and query-pack
resolution. The workflow uses the bundle linked to that Action revision. From the
repository root, create one database per compiled language (Rust and C/C++ use
`none`; Go uses explicit module build commands):

```sh
codeql database create /tmp/nexusq-codeql-rust \
  --language=rust --build-mode=none --source-root=.

codeql database create /tmp/nexusq-codeql-cpp \
  --language=c-cpp --build-mode=none --source-root=.

codeql database create /tmp/nexusq-codeql-go \
  --language=go --command='(cd bindings/go && go build ./...) && (cd arena/adapters/circl && go build ./...)' --source-root=.
```

For each database, run `codeql database analyze` with the matching built-in
`codeql/<language>-queries` security-extended suite and emit SARIF, for example:

```sh
codeql database analyze /tmp/nexusq-codeql-rust \
  codeql/rust-queries:codeql-suites/rust-security-extended.qls \
  --format=sarif-latest --output=/tmp/nexusq-rust.sarif
```

Repeat with `cpp` and `go` query packs for the corresponding databases. For
Python and GitHub Actions, use `codeql database create` with their respective
language identifiers and no build command. Local scans are optional developer
checks; GitHub Actions is the authoritative validation and merge gate for this
repository.

## Findings, false positives, and exceptions

1. Review each alert in GitHub code scanning and confirm the affected commit,
   source path, query, data flow, and reachable execution path.
2. Fix confirmed findings in a normal pull request and add regression coverage
   where practical.
3. If an alert is a false positive or not applicable, dismiss only that alert
   with the most accurate GitHub dismissal reason and a concise explanation
   referencing the code invariant or evidence. Do not suppress a query globally
   to silence one finding.
4. If a query exclusion or path exclusion is genuinely necessary, change the
   version-controlled CodeQL config in a pull request and document its scope,
   rationale, owner, and review date here.
5. Reopen the alert if later changes invalidate the original rationale.

A clean CodeQL run is evidence that the configured queries did not report a
finding in the analyzed scope. It is not proof of absence of vulnerabilities,
constant-time behavior, memory safety, cryptographic correctness, certification,
or completion of an independent security audit. CodeQL complements, but does
not replace, review, tests, fuzzing, dependency auditing, and platform-specific
security analysis.
## Dylint cryptographic rules

NEXUS-Q also maintains supplemental, heuristic Dylint rules for cryptographic code. They run in the dedicated `NEXUS-Q Dylint Crypto Rules` workflow with an isolated pinned nightly toolchain; they do not alter Fast CI or the workspace MSRV. See [Dylint cryptographic rules](DYLINT_CRYPTO_RULES.md) for scope, limitations, false-positive guidance, and the manual invocation command.

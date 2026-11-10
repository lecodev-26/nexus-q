# NEXUS-Q GitHub Actions architecture

`ci.yml` is the **only automatic workflow**. It runs on pushes to `main` and pull requests targeting `main`. It is intentionally short: Rust formatting, a locked workspace check, focused core/C ABI tests, Arena JSON contract validation, Cargo metadata validation, and the repository's unsafe-code boundary checks. It does not run long fuzz campaigns, performance benchmarks, multi-platform SDK builds, native assembly gates, or package publication.

## Manually dispatched engineering gates

Run these from **Actions → workflow → Run workflow**, selecting the branch or tag to test:

| Workflow | Purpose |
|---|---|
| `security-ci.yml` | Full workspace tests and lint/security/dependency checks, secret scanning, fuzz harness compilation, and provider-configuration regression coverage |
| `correctness-interoperability.yml` | Core interoperability regression and vendored ML-KEM/module-lattice vector suites |
| `fuzz-soak.yml` | Sequential multi-hour vault, envelope, and backup-import fuzz campaigns |
| `sdk-ci.yml` | Builds and smoke/tests for the C ABI and language bindings |
| `sdk-runtime.yml` | Builds the default RustCrypto C ABI runtime for the documented Linux, macOS, and Windows targets; artifacts are not published automatically |
| `native-runtime.yml` | Builds explicitly experimental native-provider runtime artifacts; these are not the default SDK runtime and are not published automatically |
| `native-assembly-ci.yml` | Specialized kernel/assembly, formatting, documentation, and unsafe-boundary checks |
| `native-backend-gate.yml` | Experimental native backend provenance, upstream comparison, differential/constant-time checks, and performance gate |
| `native-backend-aa-control.yml` | Informational A/A control for hosted-runner benchmark noise |
| `pqc-arena.yml` | PQC Arena registry, runner, schema, and benchmark evidence validation |
| `benchmarks.yml` | Cross-platform core benchmark runs and reproducibility metadata |
| `hybrid-benchmark.yml` | Production hybrid ML-KEM-768/X25519 benchmark evidence |
| `publish-packages.yml` | Explicitly confirmed crates.io, PyPI, and RubyGems publication from an already released, annotated version tag |
| `publish-nuget.yml` | Explicitly confirmed NuGet publication using GitHub Actions OIDC and validated RustCrypto runtime artifacts |
| `v4-release.yml` | Manual release evidence build/dry-run; actual GitHub Release publication requires a separate explicit input and the exact annotated version tag |

## Publication and security boundaries

- No registry publication is triggered by a push, pull request, or successful CI run.
- Publishing workflows default to a no-op unless the operator explicitly sets the confirmation input.
- Package publication is allowed only from an annotated `vX.Y.Z` tag whose commit matches the checked-out SHA and the existing GitHub release manifest.
- NuGet uses OIDC; do not add a long-lived NuGet API key to repository secrets.
- The ordinary SDK runtime remains RustCrypto. Experimental native-provider artifacts are separate and must not be substituted into ordinary SDK packages.
- A green CI or benchmark result is evidence for the checks actually run; it is not a claim of FIPS validation, production readiness, or completed independent audit.

The release workflow currently pins `RELEASE_VERSION` to the repository’s v4.1.2 line; update and review that constant, release notes, and package metadata together before preparing a later version. The existing v4.1.2 GitHub Release must never be overwritten.

The workflows are intentionally independent so that expensive jobs run only when requested and their results remain attributable to the exact selected ref.

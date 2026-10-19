# CI pipeline

`.github/workflows/ci-pipeline.yml` is the only workflow that automatically runs for pushes to `main` and pull requests targeting `main`. It is a sequential orchestrator: a phase starts only after the preceding required phase succeeds. Jobs inside a phase may run in parallel.

## Required phases

1. Core Rust tests, security/dependency checks, secret scan, fuzz harness compilation. The checkout initializes Git submodules recursively, including Wycheproof vectors.
2. SDK and language-binding builds/smoke tests.
3. Interoperability, ML-KEM vectors and upstream correctness suites.
4. Native assembly/kernel-specific checks, including AVX2 differential tests and the kernel unsafe-code boundary.

## Optional manual phases

Use **Actions → NEXUS-Q Sequential CI Pipeline → Run workflow** to enable additional work. All options default to false.

- `full_fuzz`: four-hour fuzz campaigns for vault, envelope and backup-import parsers (run in phase 1, so later phases wait for them).
- `run_native_gate`: experimental native backend integrity, correctness, constant-time and benchmark gate.
- `run_arena`: the full PQC Benchmark Arena.
- `run_benchmarks`: cross-platform benchmark smoke/results, hybrid benchmark, and native assembly performance gate, in sequence.
- `run_aa_control`: the ten-replica A/A noise-control experiment, which is particularly expensive.

Optional phases run only after required phases pass; performance stages are ordered and stop after a failure. Arena and benchmark workloads are not automatically launched on every push.

## Release and publishing

`v4-release.yml` and the NuGet, crates.io, PyPI and RubyGems publishers remain manual-only. They are kept separate because each registry has its own release credentials/trusted-publisher identity; do not merge or rename those publisher workflows without updating the corresponding registry configuration. Run publishing only after reviewing the exact tag/version and a green CI run.

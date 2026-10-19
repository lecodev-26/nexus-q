# NEXUS-Q sequential CI pipeline

The `ci-pipeline.yml` workflow is the single automatic entry point for pushes to `main` and pull requests targeting `main`. A manual dispatch is also available for reruns; no phase-selection inputs are needed.

## Execution order and fail-fast behavior

The eleven phases run in order. Each phase has the previous phase as a `needs` dependency, so a failure prevents later phases from starting:

1. Core Rust/security gates, secret scanning, and fuzz harness compilation.
2. SDK and language-binding builds/tests.
3. Correctness, interoperability, and upstream vectors.
4. Native assembly and kernel-specific checks.
5. Experimental native-backend gate.
6. PQC Benchmark Arena and its validation/diagnostic jobs.
7. Cross-platform benchmarks.
8. Hybrid benchmark.
9. Native assembly performance benchmark.
10. A/A benchmark noise control.
11. Final long fuzz campaigns, only after phase 10 succeeds.

## Final fuzz campaigns

The final reusable workflow runs three four-hour campaigns sequentially: vault parser, envelope parser, and backup importer. A campaign failure stops the remaining campaigns. Each job has a 250-minute timeout to allow setup plus the four-hour fuzz run.

The phase-1 fuzz job only builds the fuzz harnesses; it does not run the long campaigns early.

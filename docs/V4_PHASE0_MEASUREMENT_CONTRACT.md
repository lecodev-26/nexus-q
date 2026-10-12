# V4 Phase 0 — Measurement contract

**Status:** implemented in the local working branch; pending real CI validation. This document defines the intended comparison boundary and does not certify measured performance.

## Conventional operation set

The gate compares these nine FIPS operations, by exact `(algorithm, parameter_set, operation)` key:

- ML-KEM-768: keygen, encaps, decaps
- ML-KEM-1024: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

The JSONL field `measurement.comparison_contract` must equal `fips_operation_v1` for each of these records. `measurement.measurement_scope` remains implementation-specific and is not overwritten to pretend that RustCrypto/nexusq-core and AWS-LC EVP use the same implementation path. Cached ML-DSA verification is a separate `cached_verification_diagnostic_v1` record and is excluded from the nine-operation gate.

## Timed boundary

The intended unit is one public FIPS primitive operation with a pre-existing valid input/key fixture. Harness serialization, output copying, result formatting, and reusable context construction are excluded. Costs that are part of the implementation's required public operation call remain measured. AWS-LC KEM contexts are initialized before samples; its sign/verify context allocations are outside samples, while the API initialization is repeated inside each sample because it is required to prepare each one-shot operation. RustCrypto ML-KEM uses the direct operation API; ML-DSA uses the `nexusq-core` wrapper. These implementation differences remain explicit in `measurement_scope` and `measurement_method`; a shared contract does not imply that the libraries have identical internals.

## Sampling and metadata

Both runners use at least 1,000 measured samples and 100 warmups in the CI job, preserve raw nanosecond samples, and report min/median/p95/population standard deviation using the shared nearest-rank p95 convention. Cycle samples are included where the platform counter is available; otherwise `cycle_counter_source` is `unavailable`. CPU model/features, frequency if exposed, governor (or explicit `unknown`), optimization profile, fixed run order, toolchain provenance and Rust runner lockfile SHA-256 are captured and validated.

## Enforced gate

The current threshold is `NEXUSQ_MAX_RATIO=1.5`. For every one of the nine operations, both NEXUS-Q median and p95 divided by the pinned AWS-LC median and p95 respectively must be less than or equal to the threshold. Missing comparator records, a contract mismatch, invalid metadata, failed self-checks, malformed schema records, or threshold regressions fail the CI job. The report contains all per-operation ratios and the reason for any failure.

The threshold is the current milestone only; future milestones may tighten it to 1.2x, 1.05x and 1.00x when the project explicitly changes the configured value. A gate pass on one run is not evidence for a public performance-leadership claim; reproducibility and later phase acceptance criteria still apply.

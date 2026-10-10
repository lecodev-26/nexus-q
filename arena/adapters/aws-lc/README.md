# AWS-LC Arena adapter

This adapter targets AWS-LC mainline at immutable commit `ec05f25`.

Supported Arena workloads in this adapter:

- ML-KEM-768: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

AWS-LC documents FIPS 203 ML-KEM and FIPS 204 ML-DSA and exposes a generic EVP KEM API. The adapter uses the native EVP API rather than TLS/hybrid protocol groups so the workload remains a primitive-to-primitive comparison.

AWS-LC uses rolling mainline releases in addition to LTS branches, so the Arena records the immutable source commit rather than inventing a semantic version for this benchmark target. CI must record the runtime AWS-LC version string in the result metadata.

A successful build or schema check alone is not a performance claim; benchmark evidence must be comparable and reviewed.


## Measurement controls

The adapter accepts `AWSLC_ITERATIONS` and `AWSLC_WARMUPS` as positive-integer
measurement controls. Defaults remain 20 measured operations and 3 warmups for
exploratory runs; the V4 acceptance harness sets these to at least `1000`
and `100`, respectively. Values above 1,000,000 or malformed values fail fast.

Each measured operation is timed independently with `clock_gettime(CLOCK_MONOTONIC)`. JSONL records include all raw samples in `measurement.samples_ns`; `latency_ns` is the median, and `statistics` reports sample count, minimum, median, p95, and population standard deviation. CI checks sample counts, statistic ordering, and consistency between the median and `latency_ns`.

This removes the aggregate-mean limitation, but does not by itself establish a fair speed comparison. Phase 0 remains open until primitive semantics and parameter sets are equivalent, host/build conditions and statistics are comparable, comparator coverage gaps (including ML-KEM-1024) are addressed or explicitly bounded, and CI artifacts are reviewed. A green schema/build gate is not evidence of performance leadership.

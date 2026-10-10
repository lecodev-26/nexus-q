# AWS-LC Arena adapter

This adapter targets AWS-LC mainline at immutable commit `ec05f25`.

Supported Arena workloads in this adapter:

- ML-KEM-768: keygen, encaps, decaps
- ML-KEM-1024: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

AWS-LC documents FIPS 203 ML-KEM and FIPS 204 ML-DSA and exposes a generic EVP KEM API. The adapter uses the native EVP API rather than TLS/hybrid protocol groups so the workload remains a primitive-to-primitive comparison.

AWS-LC uses rolling mainline releases in addition to LTS branches, so the Arena records the immutable source commit rather than inventing a semantic version for this benchmark target. CI must record the runtime AWS-LC version string in the result metadata.

A successful build or schema check alone is not a performance claim; benchmark evidence must be comparable and reviewed.


## Measurement controls

The adapter accepts `AWSLC_ITERATIONS` and `AWSLC_WARMUPS` as positive-integer
measurement controls. Defaults remain 20 measured operations and 3 warmups for
exploratory runs; the V4 acceptance harness sets these to at least `1000`
and `100`, respectively. Values above 1,000,000 or malformed values fail fast.

Each measured operation is timed independently with `clock_gettime(CLOCK_MONOTONIC)`. JSONL records include all raw samples in `measurement.samples_ns`; `latency_ns` is the median, and `statistics` reports sample count, minimum, median, p95, and population standard deviation. CI checks sample counts, statistic ordering, and consistency between the median and `latency_ns`. Both runners must also pass a pre-measurement encapsulation/decapsulation round-trip check with matching shared secrets for both parameter sets.

The NEXUS-Q runner measures RustCrypto's direct `ml-kem` API for both ML-KEM-768 and ML-KEM-1024 (without the NEXUS-Q serialization/zeroization wrapper); the AWS-LC runner measures its public EVP KEM API. The AWS-LC timing therefore includes EVP context creation for key generation and encapsulation/decapsulation, while the RustCrypto timing measures the direct primitive call (and keeps the ML-KEM-1024 ciphertext serialization copy outside the timed interval). These are comparable standardized primitive operations and parameter sets, but not identical API-layer costs. Results must be labeled and interpreted as implementation/API-path measurements, not as a pure isolated-core comparison. A stricter core-to-core comparison would require a comparable low-level API or a separate calibrated harness.

This removes the aggregate-mean limitation and closes the AWS-LC ML-KEM-1024 coverage gap, but does not by itself establish a fair speed comparison. Phase 0 remains open until remaining API-layer semantics and host/build conditions are reviewed, frequency/governor metadata is captured where available, repeated runs are reproducible, and CI artifacts are reviewed. A green schema/build gate is not evidence of performance leadership.

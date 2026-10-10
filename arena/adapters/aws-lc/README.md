# AWS-LC Arena adapter

This adapter targets AWS-LC mainline at immutable commit `ec05f25`.

Supported Arena workloads in this adapter:

- ML-KEM-768: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

AWS-LC documents FIPS 203 ML-KEM and FIPS 204 ML-DSA and exposes a generic EVP KEM API. The adapter uses the native EVP API rather than TLS/hybrid protocol groups so the workload remains a primitive-to-primitive comparison.

AWS-LC uses rolling mainline releases in addition to LTS branches, so the Arena records the immutable source commit rather than inventing a semantic version for this benchmark target. CI must record the runtime AWS-LC version string in the result metadata.

No benchmark result is claimed until CI executes this adapter.


## Measurement controls

The adapter accepts `AWSLC_ITERATIONS` and `AWSLC_WARMUPS` as positive-integer
measurement controls. Defaults remain 20 measured operations and 3 warmups for
exploratory runs; the V4 acceptance harness should set these to at least `1000`
and `100`, respectively. Values above 1,000,000 or malformed values fail fast.

**Important limitation:** this adapter still reports an aggregate mean for each
operation rather than raw per-operation samples and distribution statistics.
Changing iteration counts alone does not make it statistically equivalent to
the NEXUS-Q runner. Phase 0 remains blocked until AWS-LC emits individual
samples and median, p95, and standard deviation, and both implementations are
run under equivalent host/build conditions.

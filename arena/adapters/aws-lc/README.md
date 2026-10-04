# AWS-LC Arena adapter

This adapter targets AWS-LC mainline at immutable commit `ec05f25`.

Supported Arena workloads in this adapter:

- ML-KEM-768: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

AWS-LC documents FIPS 203 ML-KEM and FIPS 204 ML-DSA and exposes a generic EVP KEM API. The adapter uses the native EVP API rather than TLS/hybrid protocol groups so the workload remains a primitive-to-primitive comparison.

AWS-LC uses rolling mainline releases in addition to LTS branches, so the Arena records the immutable source commit rather than inventing a semantic version for this benchmark target. CI must record the runtime AWS-LC version string in the result metadata.

No benchmark result is claimed until CI executes this adapter.

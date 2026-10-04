# Botan Arena adapter

This adapter targets the Botan 3.13.0 release and uses Botan's public C++ public-key API.

Workloads:

- ML-KEM-768: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

The Arena parameter name `65` maps to Botan's `ML-DSA-6x5` parameter spelling. KEM measurements request the raw KEM shared secret so they remain primitive-to-primitive comparisons rather than KDF-inclusive workflows.

The CI job clones the immutable `3.13.0` release tag, records the resolved commit in the environment, builds Botan, compiles this adapter, runs it, and validates six normalized result rows.

No benchmark result is claimed until CI executes this adapter.

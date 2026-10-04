# RustCrypto KEMs Arena adapter

This adapter pins two separate RustCrypto/KEMs release commits because the Arena compares independently versioned crates from the same repository:

- `ml-kem` 0.3.2 at commit `440768245bba59784b504269cb3087a6c21af45c`
- `hqc-kem` 0.1.0-rc.0 at commit `1a50023ab1dcebaaf500646589c76a3f0efade1f`

Workloads:

- ML-KEM-768: keygen, encaps, decaps
- HQC-128: keygen, encaps, decaps

ML-KEM-768 uses the crate's FIPS 203 implementation. HQC-128 is the NIST Level 1 parameter set from the pinned HQC-KEM release. These are primitive KEM measurements; no protocol or hybrid wrapper is included.

The registry keeps the implementation name broad (`RustCrypto KEMs`) while the result metadata records each crate version and commit. No benchmark result is claimed until CI executes the adapter.

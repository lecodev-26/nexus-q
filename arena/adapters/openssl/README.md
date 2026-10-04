# OpenSSL Arena adapter

This adapter targets OpenSSL **3.5.9**, the current 3.5 LTS release, using the provider-based EVP APIs for plain PQC primitives.

Workloads:

- ML-KEM-768: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify
- SLH-DSA-SHAKE-128f: keygen, sign, verify

The adapter deliberately benchmarks primitive operations, not `openssl` CLI process startup and not hybrid TLS groups. OpenSSL's TLS support for X25519MLKEM768 is therefore outside this primitive matrix.

The CI source is pinned to the immutable `openssl-3.5.9` release tag. No benchmark result is claimed until CI executes the adapter.

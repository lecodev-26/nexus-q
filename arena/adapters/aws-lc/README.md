# AWS-LC Arena adapter

The adapter uses the pinned AWS-LC revision selected by the native backend gate and emits raw per-operation nanosecond samples. The legacy intermediate gate retains its historical AWS-LC-only comparison at a 1.5x limit.

For key generation, timed samples include export of the raw public and secret key bytes and per-sample output-buffer allocations, matching the encoded-key outputs returned by NEXUS-Q. Those rows use `measurement_scope=reference_implementation_operation`.

For encapsulation, decapsulation, signing, and verification, the current public EVP adapter imports the key and creates operation contexts before the timed samples. Those rows are explicitly marked `aws_lc_evp_preimported_public_key` or `aws_lc_evp_preimported_secret_key`. The strict best-comparator evaluator excludes those rows for these operations because the encoded-key import is outside the timed sample; liboqs and CIRCL adapters include parsing of encoded keys. This prevents a prepared-key AWS-LC result from being treated as a directly comparable encoded-key operation.

The benchmark-only NEXUS-Q RNG bridge calls the locked AWS-LC `RAND_bytes` symbol from C so the native kernel and AWS-LC runner use the same CSPRNG without a C-to-Rust-to-C callback. The default production backend remains on `getrandom`.

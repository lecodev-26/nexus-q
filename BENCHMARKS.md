# Benchmarking

Phase 17 records measured performance without making platform claims that have not been executed.

## Android/Termux baseline (measured locally)

Command: cargo bench -p nexusq-core --bench crypto_baseline -- --nocapture
Iterations: 20 for crypto operations; 3 for Vault operations.
Environment: the project's Android/Termux development device; results are informational and environment-sensitive.

| Operation | Mean per operation |
| --- | ---: |
| ML-KEM-768+X25519 keygen | 147,227 ns |
| ML-KEM-1024+X25519 encaps | 500,573 ns |
| ML-KEM-1024+X25519 decaps | 452,677 ns |
| ML-DSA-65 keygen | 858,969 ns |
| SLH-DSA-SHAKE-128f keygen | 13,131,888 ns |
| Ed25519 sign | 65,292 ns |
| Ed25519 verify | 195,365 ns |
| AES-256-GCM encrypt | 692 ns |
| AES-256-GCM decrypt | 704 ns |
| Vault open | 71,692 ns |
| Vault unlock | 301,479,513 ns |
| Identity key rotation | 67,795 ns |

The Vault unlock number includes the configured password KDF and is therefore expected to dominate the operation cost.

## CI matrix

`.github/workflows/benchmarks.yml` runs the same benchmark on x86_64 Linux and ARM64 Linux and archives toolchain/metadata. RISC-V and embedded execution require dedicated runners or hardware; those are release/audit gates, not simulated by cross compilation.

Benchmark output is environment-sensitive (CPU frequency, thermal state, OS scheduler, compiler version). Results are comparable only when toolchain, target, workload and environment are recorded together.

API latency and storage-specific endurance benchmarks remain release-gate extensions and must be measured on representative deployments rather than inferred from local Android timings.

# PQC Benchmark Arena Protocol v1

## 1. Benchmark units

KEM:
- keygen
- encaps
- decaps

Signatures:
- keygen
- sign
- verify

Optional system/protocol tiers:
- complete KEM workflow
- complete signature workflow
- TLS/PQ-TLS handshake
- NEXUS-Q API/vault workflows

## 2. Required metadata

Every measured result must identify:

- implementation
- implementation version
- source commit when available
- algorithm
- parameter set
- operation
- architecture/target
- CPU model
- CPU feature set
- operating system
- compiler and compiler version
- optimization profile
- benchmark harness version
- iteration count
- warmup policy
- measurement timestamp (Unix epoch nanoseconds)

## 3. Two performance views

### Real-world
The best documented production-oriented configuration reasonably supported by the implementation.

### Controlled
A configuration chosen to reduce implementation-specific environmental differences. It must document any remaining differences.

Both views are useful; neither replaces the other.

## 4. Statistical policy

The first implementation records mean latency in nanoseconds plus sample count. Future harnesses may add median, p95/p99, standard deviation and confidence intervals.

Results from different benchmark runs must not be merged into one number unless the environment is compatible.

## 5. Memory

Peak process memory is optional in v1 of the data schema because measurement methods differ significantly across operating systems. When available it must state the measurement method.

## 6. Ranking

No global winner is produced initially. Reports are separated into:

- performance
- size
- memory
- portability
- security evidence
- production maturity
- protocol performance

Security status always overrides raw performance for the secure ranking.

## 7. Inclusion policy

An implementation is benchmark-eligible only when:

- the algorithm/parameter set is clearly identifiable;
- the implementation is buildable on the target;
- the benchmark operation is semantically equivalent;
- the source revision is recorded;
- the security status is known.

Experimental implementations remain clearly labeled. Deprecated or cryptographically broken algorithms are historical-only.

## 8. Platform policy

x86_64 and ARM64 are first-class CI targets.

RISC-V and embedded targets require real execution on dedicated hardware/runners. Cross compilation alone never produces an execution result.

## 9. First external adapter: liboqs

The first external Arena adapter is Open Quantum Safe liboqs 0.16.0, pinned to upstream commit 5a1a854.

The initial comparison matrix is intentionally limited to standardized plain primitives:

- ML-KEM-768: keygen, encaps, decaps
- ML-KEM-1024: keygen, encaps, decaps
- ML-DSA-65: keygen, sign, verify

NEXUS-Q's ML-KEM+X25519 hybrid constructions are not compared against plain liboqs ML-KEM results. The two measurements must use semantically equivalent plain constructions.

The liboqs adapter is CI-only when the local environment does not provide liboqs. It records the liboqs version/commit, target, OS, CPU metadata, compiler, optimization profile and implementation-reported serialized sizes.

## 10. Reproducibility

A future Arena release must pin:

- source revision
- benchmark harness revision
- compiler/toolchain
- target
- CPU features
- optimization flags
- benchmark configuration

Generated reports must be derivable from normalized result files.

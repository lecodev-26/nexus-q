# NEXUS-Q v2 — V2-06 SIMD and CPU Backend Evaluation

Status: **evaluation complete; no architecture-specific backend retained in V2-06**.

## Scope

V2-06 evaluates whether NEXUS-Q can safely add SIMD/CPU-specific acceleration while preserving:

- identical FIPS 203/FIPS 204 algorithms and parameter sets;
- constant-time/security expectations of the existing implementations;
- portable scalar behavior on unsupported CPUs;
- the existing canonical Arena workload;
- the \`nexusq-core\` unsafe-code policy.

The phase is an evaluation gate, not permission to add architecture-specific code without measured evidence.

## Current backend inventory

The production ML-KEM and ML-DSA implementations are RustCrypto crates:

- \`ml-kem\` 0.3.2 is vendored and patched into the workspace.
- \`module-lattice\` 0.2.3 is vendored and patched into the workspace.
- \`ml-dsa\` remains the upstream dependency and consumes \`module-lattice\`.

The vendored \`ml-kem\` and \`module-lattice\` manifests expose \`alloc\`, \`getrandom\`, \`zeroize\`, \`ctutils\` and related packaging features, but no AVX2, AVX-512, NEON or other explicit SIMD backend feature.

The current NTT and field arithmetic are portable Rust implementations. V2-03/V2-04 optimizations retained compiler inlining changes only; they did not introduce architecture-specific instructions.

## Runtime-dispatch safety

Rust supports runtime CPU feature detection and \`#[target_feature]\` functions, but calling code compiled for an unsupported feature is undefined behavior. Runtime dispatch therefore requires a correctly isolated architecture-specific implementation plus a portable fallback.

NEXUS-Q's \`nexusq-core\` crate currently declares:

\`[lints.rust]\`
\`unsafe_code = "forbid"\`

Explicit architecture intrinsics and the usual runtime-dispatch pattern require unsafe boundaries. That does not make SIMD inherently unsafe, but it means a backend cannot be added to the current core merely by sprinkling intrinsics into the existing scalar implementation.

## Evaluation result

### Option A — build-wide \`-C target-cpu=native\`

Rejected as a production backend.

It can improve code generation for the build host, but it is not runtime dispatch. A binary built for one CPU cannot be treated as portable across machines with weaker instruction sets. It is therefore unsuitable as the published NEXUS-Q backend strategy.

It remains useful as an exploratory benchmark configuration for V2-10 investigations.

### Option B — per-function AVX2/AVX-512/NEON dispatch

Not retained in V2-06.

A correct implementation would require:

1. an architecture-specific implementation;
2. runtime feature detection;
3. a safe dispatch boundary;
4. a scalar fallback;
5. KAT/interoperability coverage for every backend;
6. reproducible Arena evidence showing a material benefit;
7. side-channel review of the optimized arithmetic.

No such implementation exists in the current dependency backend, and V2-06 has no measured evidence justifying a new hand-written NTT implementation.

### Option C — dependency-provided SIMD backend

Not available in the pinned production backend.

The current \`ml-kem\` 0.3.2 and \`module-lattice\` 0.2.3 manifests do not expose an opt-in architecture-specific SIMD backend. Changing cryptographic providers solely to obtain SIMD would also change the implementation/backend boundary and belongs to V2-07, where backend strategy is explicitly evaluated.

## Decision

**No SIMD/CPU-specific backend is retained by V2-06.**

This is an intentional negative result, not an unfinished optimization:

- the portable scalar path remains the production fallback;
- no unsafe code is introduced into \`nexusq-core\`;
- no CPU-dependent behavior is enabled globally;
- no cryptographic algorithm or parameter changes are made;
- no performance claim is made without Arena evidence.

The evidence-backed next step is V2-07: define the backend and primitive strategy, including whether a separately audited/native backend is justified and how it can coexist with the portable Rust implementation.

## Evidence hierarchy

1. V2-02 hotspot profile identifies NTT/polynomial arithmetic as optimization candidates.
2. V2-03/V2-04 retained only portable compiler-level optimizations with measured local benefit.
3. Current production dependency manifests expose no explicit SIMD backend feature.
4. Rust's target-feature model requires runtime-safe dispatch and rejects unsupported feature execution as undefined behavior.
5. V2-10 remains the authoritative performance gate.

## Security boundary

No secret-dependent branch, memory access pattern, cryptographic parameter, serialization rule or zeroization behavior was changed by V2-06.

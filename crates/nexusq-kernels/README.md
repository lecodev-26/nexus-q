# NEXUS-Q kernel dispatch

This crate contains portable scalar reference kernels and the dispatch boundary for
future architecture-specific implementations.

## Safety and selection policy

The scalar implementation is the correctness reference and the only selectable
backend in the current scaffold. Runtime CPU feature detection is diagnostic
metadata only: detecting an instruction set does **not** mean a matching kernel
exists or is eligible for use.

An optimized backend must not be enabled by default until it has passed the
Issue #23 gates:

- bit-exact differential tests against the scalar reference;
- relevant known-answer and interoperability vectors;
- fuzzing and malformed-input checks;
- constant-time and secret-handling review, including zeroization requirements;
- repeated same-hardware benchmarks with median, p95, and dispersion reported.

No unsafe or architecture-specific kernel is enabled by this dispatch layer.

## Inspecting the current decision

```rust
use nexusq_kernels::dispatch::{dispatch_info, selected_backend, Backend};

let info = dispatch_info();
assert_eq!(selected_backend(), Backend::Scalar);
println!("backend: {:?}; reason: {:?}", info.backend, info.reason);
println!("CPU capabilities: {:?}", info.cpu);
```

The decision is initialized once per process and cached. The reported CPU
capabilities are informational; they are not a promise of accelerated execution.

## Forcing the scalar path

Scalar is already the default and only available backend. For explicit operational
intent, set `NEXUSQ_FORCE_SCALAR=1` (also accepts `true`, `yes`, or `on`).
The crate feature `force-scalar` provides a compile-time equivalent; enable it
in the `nexusq-kernels` dependency declaration when configuring a downstream build.

The feature does not change the algorithm today; it records an explicit preference
in the dispatch metadata. The environment variable is read on first dispatch
initialization. Changing it later in the same process does not alter the cached
decision.

## Detected capabilities

- x86_64: AVX2, AVX-512F, and BMI2.
- AArch64: NEON/Advanced SIMD (mandatory on AArch64) and SHA-3 instructions.
- Other targets: all capability flags remain false until target-specific detection
  is implemented.

Detection is performed with safe standard-library feature-detection macros.
Architecture-specific code must still be guarded by runtime checks and compiled
for an appropriate target feature before it can be called.

## Current limitations

- Only `Backend::Scalar` exists; AVX2 and NEON implementations are future work.
- The scalar ML-KEM routines are correctness-oriented reference code, not a
  constant-time production implementation.
- Dispatch metadata does not currently select separate Keccak or ML-KEM kernels.
- This API is experimental and may evolve during V4; it is not a stable semver
  contract yet.

## Backend contract

`backend::KernelBackend` defines the common primitive interface for Keccak-f[1600],
SHAKE128/SHAKE256, and selected ML-KEM polynomial operations. `backend::ScalarBackend`
forwards to the existing scalar reference implementation and is currently the only
implementation. The contract is an integration seam for differential testing and
future AVX2/NEON work; it does not imply that dispatch uses this trait yet, nor that
any optimized implementation exists or is production-safe.

Example of an explicit reference call:

```rust
use nexusq_kernels::backend::{KernelBackend, ScalarBackend};

let mut state = [0_u64; 25];
ScalarBackend::keccak_f1600(&mut state);
```

The backend contract tests compare wrapper calls to the scalar functions. They are
source-level test coverage only until the project's CI runs them; local Cargo checks
are intentionally deferred to the GitHub Actions phase.

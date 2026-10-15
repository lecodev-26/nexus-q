# Native Assembly — Correctness and Security Gates

Every native kernel must satisfy the following before it can be used to support a performance claim.

## Arithmetic and functional correctness
- Keep a scalar oracle/reference path and compare every SIMD/assembly output bit-for-bit.
- Cover random inputs, all relevant coefficient boundaries, negative/intermediate representations, parameter-set variants and adversarial edge cases.
- Document the valid range before and after every multiply, accumulation, lazy reduction and narrowing conversion.
- Prove modular reduction bounds for the actual maximum intermediate; do not reuse ML-KEM reductions for ML-DSA.
- Test exact dispatch selection on supported CPUs and force the scalar fallback in CI.
- Test the actual top-level operation path; microkernel tests alone do not establish end-to-end correctness.
- Preserve NIST known-answer vectors, malformed-input behavior, public APIs and byte encodings.

## Constant-time and secret handling
- No secret-dependent branches, memory indices or dispatch decisions in secret-bearing paths.
- Document all `unsafe` blocks and assembly preconditions; keep kernel unsafe code isolated from `nexusq-core`.
- Audit register clobbers, stack use, alignment, ABI compliance, AVX/SSE transition handling and CPU feature checks.
- Preserve zeroization of secret buffers and review temporary/spilled secrets; do not rely on clearing vector registers as a substitute for sound lifetime design.
- Treat signing rejection loops and public rejection sampling according to their algorithmic semantics; do not broaden variable-time behavior.
- Add timing/statistical tests, sanitizer/fuzz coverage and architecture-specific review where available; document unsupported validation rather than claiming it passed.

## Integration and fallback
- Assembly must be called from the real production operation, not merely compiled or benchmarked in isolation.
- Runtime dispatch must never execute unsupported instructions; a scalar fallback remains available.
- Public API, key/ciphertext/signature encodings, storage and wire formats remain compatible.
- CI must retain raw correctness and benchmark evidence tied to the exact commit.

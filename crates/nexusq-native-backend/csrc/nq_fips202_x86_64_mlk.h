/* FIPS202 backend for NEXUS-Q on x86-64 (MLK):
 *  - 4-way: upstream AVX2 backend, runtime-gated on AVX2. AWS-LC instead uses
 *    s2n-bignum sha3_keccak4_f1600_alt (same signature and state layout,
 *    different code). Measured on GitHub runners, the s2n routine was ~1%
 *    slower on AMD EPYC 7763 and neutral on Zen 4 (runs 38798035934,
 *    38798036136), so upstream's routine is kept (see NATIVE_BACKEND.md, D9).
 *  - 1-way: s2n-bignum sha3_keccak_f1600, the routine AWS-LC uses on x86-64.
 *    Baseline x86-64 instructions only, so no capability check is needed. */
#ifndef NQ_FIPS202_X86_64_MLK_H
#define NQ_FIPS202_X86_64_MLK_H
#include "src/fips202/native/x86_64/keccak_f1600_x4_avx2.h"
#if !defined(NQ_NO_S2N_KECCAK)
#define MLK_USE_NATIVE_FIPS202_X1
#if !defined(__ASSEMBLER__)
void nq_sha3_keccak_f1600(uint64_t a[25], const uint64_t rc[24]);
MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_keccak_f1600_x1_native(uint64_t *state)
{
  nq_sha3_keccak_f1600(state, mlk_keccakf1600_round_constants);
  return MLK_NATIVE_FUNC_SUCCESS;
}
#endif /* !__ASSEMBLER__ */
#endif /* !NQ_NO_S2N_KECCAK */
#endif

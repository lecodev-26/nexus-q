/* FIPS202 backend for NEXUS-Q on x86-64 (MLK). Mirrors AWS-LC ec05f25e
 * (crypto/fipsmodule/sha/keccak1600.c) on x86-64:
 *  - 4-way: s2n-bignum sha3_keccak4_f1600_alt (AVX2), runtime-gated on AVX2,
 *    through the official MLK_USE_NATIVE_FIPS202_X4 hook. Same state layout
 *    (four consecutive 25-lane states) and signature as upstream's
 *    mlk_keccak_f1600_x4_avx2_asm, which remains available for A/B via the
 *    `upstream-x4-keccak` feature (NQ_UPSTREAM_X4_KECCAK).
 *  - 1-way: s2n-bignum sha3_keccak_f1600 (baseline x86-64 ISA, no capability
 *    check needed) through MLK_USE_NATIVE_FIPS202_X1; `upstream-c-keccak`
 *    (NQ_NO_S2N_KECCAK) restores upstream's portable C permutation. */
#ifndef NQ_FIPS202_X86_64_MLK_H
#define NQ_FIPS202_X86_64_MLK_H
#if defined(NQ_UPSTREAM_X4_KECCAK)
#include "src/fips202/native/x86_64/keccak_f1600_x4_avx2.h"
#else
#include "src/common.h"
/* Keeps upstream's constant tables (mlk_keccakf1600_round_constants,
 * mlk_keccak_rho8/56) compiled; the upstream x4 routine is then unused. */
#define MLK_FIPS202_X86_64_NEED_X4_AVX2
#define MLK_USE_NATIVE_FIPS202_X4
#if !defined(__ASSEMBLER__)
#include "src/fips202/native/api.h"
#include "src/fips202/native/x86_64/src/fips202_native_x86_64.h"
void nq_sha3_keccak4_f1600_alt(uint64_t a[100], const uint64_t rc[24],
                               const uint64_t rho8[4], const uint64_t rho56[4]);
MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_keccak_f1600_x4_native(uint64_t *state)
{
  if (!mlk_sys_check_capability(MLK_SYS_CAP_X86_64_AVX2))
  {
    return MLK_NATIVE_FUNC_FALLBACK;
  }
  nq_sha3_keccak4_f1600_alt(state, mlk_keccakf1600_round_constants,
                            mlk_keccak_rho8, mlk_keccak_rho56);
  return MLK_NATIVE_FUNC_SUCCESS;
}
#endif /* !__ASSEMBLER__ */
#endif /* !NQ_UPSTREAM_X4_KECCAK */
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

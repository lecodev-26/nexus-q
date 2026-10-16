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
#if !defined(__ASSEMBLER__)
#define MLK_USE_NATIVE_FIPS202_X4_XOR_BYTES
#define MLK_USE_NATIVE_FIPS202_X4_EXTRACT_BYTES
#endif
#include "src/fips202/native/x86_64/keccak_f1600_x4_avx2.h"
#if !defined(__ASSEMBLER__)
#include <string.h>

/* The upstream x4 sponge wrapper copies/XORs bytes one at a time. AWS-LC's
 * equivalent processes full 64-bit lanes. Keep arbitrary offsets and partial
 * tails on the upstream path; accelerate only the aligned full-lane case.
 * This hook is baseline x86-64 C (no AVX2 assumption), so it is safe even when
 * runtime dispatch selects the portable permutation. */
MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_keccakf1600_xor_bytes_x4_native(
    uint64_t *state, const unsigned char *data0, const unsigned char *data1,
    const unsigned char *data2, const unsigned char *data3, unsigned offset,
    unsigned length)
{
  if ((offset & 7u) != 0 || (length & 7u) != 0)
    return MLK_NATIVE_FUNC_FALLBACK;

  const unsigned lane = offset / sizeof(uint64_t);
  const unsigned words = length / sizeof(uint64_t);
  for (unsigned i = 0; i < words; i++)
  {
    uint64_t word;
    memcpy(&word, data0 + 8u * i, sizeof(word));
    state[lane + i] ^= word;
    memcpy(&word, data1 + 8u * i, sizeof(word));
    state[25u + lane + i] ^= word;
    memcpy(&word, data2 + 8u * i, sizeof(word));
    state[50u + lane + i] ^= word;
    memcpy(&word, data3 + 8u * i, sizeof(word));
    state[75u + lane + i] ^= word;
  }
  return MLK_NATIVE_FUNC_SUCCESS;
}

MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_keccakf1600_extract_bytes_x4_native(
    uint64_t *state, unsigned char *data0, unsigned char *data1,
    unsigned char *data2, unsigned char *data3, unsigned offset,
    unsigned length)
{
  if ((offset & 7u) != 0 || (length & 7u) != 0)
    return MLK_NATIVE_FUNC_FALLBACK;

  const unsigned lane = offset / sizeof(uint64_t);
  const unsigned words = length / sizeof(uint64_t);
  for (unsigned i = 0; i < words; i++)
  {
    memcpy(data0 + 8u * i, &state[lane + i], sizeof(uint64_t));
    memcpy(data1 + 8u * i, &state[25u + lane + i], sizeof(uint64_t));
    memcpy(data2 + 8u * i, &state[50u + lane + i], sizeof(uint64_t));
    memcpy(data3 + 8u * i, &state[75u + lane + i], sizeof(uint64_t));
  }
  return MLK_NATIVE_FUNC_SUCCESS;
}
#endif /* !__ASSEMBLER__ */

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

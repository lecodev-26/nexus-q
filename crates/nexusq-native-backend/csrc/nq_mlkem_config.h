#ifndef MLK_CONFIG_H
#define MLK_CONFIG_H
#ifndef MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_PARAMETER_SET 768
#endif
#define MLK_CONFIG_NAMESPACE_PREFIX nq_mlkem
#define MLK_CONFIG_MULTILEVEL_BUILD
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#include "nq_common.h"
/* Native backend: always compiled (pure .S, no -mavx2 for C), selected at
 * runtime through mlk_sys_check_capability -- the AWS-LC integration model. */
#if defined(__x86_64__) && defined(__linux__) && !defined(NQ_PORTABLE_ONLY)
#define MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLK_CONFIG_ARITH_BACKEND_FILE "native/x86_64/meta.h"
#define MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLK_CONFIG_FIPS202_BACKEND_FILE "nq_fips202_x86_64_mlk.h"
#elif defined(__aarch64__) && !defined(NQ_PORTABLE_ONLY)
/* Upstream-reviewed AArch64 NEON arithmetic and Keccak assembly. */
#define MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLK_CONFIG_ARITH_BACKEND_FILE "native/aarch64/meta.h"
#define MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLK_CONFIG_FIPS202_BACKEND_FILE "fips202/native/auto.h"
#endif
#define MLK_CONFIG_CUSTOM_CAPABILITY_FUNC
#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#if !defined(__ASSEMBLER__) && !defined(NQ_MLK_FUNCS)
#define NQ_MLK_FUNCS
#include "src/sys.h"
static MLK_INLINE int mlk_sys_check_capability(mlk_sys_cap cap)
{
#if defined(__x86_64__)
  if (cap == MLK_SYS_CAP_X86_64_AVX2)
  {
    return nq_cpu_avx2_bmi2();
  }
#endif
#if defined(__aarch64__)
  /* Advanced SIMD/NEON is mandatory in the AArch64 execution state. */
  if (cap == MLK_SYS_CAP_AARCH64_NEON)
  {
    return 1;
  }
#endif
  (void)cap;
  return 0;
}
static MLK_INLINE int mlk_randombytes(uint8_t *ptr, size_t len)
{
  return nq_randombytes(ptr, len);
}
#endif
#endif

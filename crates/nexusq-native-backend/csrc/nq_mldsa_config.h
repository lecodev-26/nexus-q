#ifndef MLD_CONFIG_H
#define MLD_CONFIG_H
#define MLD_CONFIG_PARAMETER_SET 65
#define MLD_CONFIG_NAMESPACE_PREFIX nq_mldsa65
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static
#include "nq_common.h"
#if defined(__x86_64__) && defined(__linux__) && !defined(NQ_PORTABLE_ONLY)
#define MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLD_CONFIG_ARITH_BACKEND_FILE "native/x86_64/meta.h"
#define MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLD_CONFIG_FIPS202_BACKEND_FILE "nq_fips202_x86_64_mld.h"
#endif
#define MLD_CONFIG_CUSTOM_CAPABILITY_FUNC
#define MLD_CONFIG_CUSTOM_RANDOMBYTES
#if !defined(__ASSEMBLER__) && !defined(NQ_MLD_FUNCS)
#define NQ_MLD_FUNCS
#include "src/sys.h"
static MLD_INLINE int mld_sys_check_capability(mld_sys_cap cap)
{
#if defined(__x86_64__)
  if (cap == MLD_SYS_CAP_X86_64_AVX2)
  {
    return nq_cpu_avx2_bmi2();
  }
#endif
  (void)cap;
  return 0;
}
static MLD_INLINE int mld_randombytes(uint8_t *ptr, size_t len)
{
  return nq_randombytes(ptr, len);
}
#endif
#endif

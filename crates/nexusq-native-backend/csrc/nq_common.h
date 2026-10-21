/* NEXUS-Q native backend glue shared by mlkem-native and mldsa-native. */
#ifndef NQ_COMMON_H
#define NQ_COMMON_H
#if !defined(__ASSEMBLER__)
#include <stddef.h>
#include <stdint.h>
/* Implemented in Rust (OS CSPRNG via getrandom). Returns 0 on success. */
int nq_randombytes(uint8_t *out, size_t len);
/* Runtime CPU dispatch, same policy as AWS-LC: AVX2 && BMI2 (OS-enabled).
 * GCC/Clang expose this builtin on x86. Other architectures and compilers use
 * the portable implementation and must never be treated as AVX2-capable. */
static inline int nq_cpu_avx2_bmi2(void)
{
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__x86_64__) || defined(__i386__))
  return __builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi2");
#else
  return 0;
#endif
}
#endif
#endif

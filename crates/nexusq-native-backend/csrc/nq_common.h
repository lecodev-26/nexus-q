/* NEXUS-Q native backend glue shared by mlkem-native and mldsa-native. */
#ifndef NQ_COMMON_H
#define NQ_COMMON_H
#if !defined(__ASSEMBLER__)
#include <stddef.h>
#include <stdint.h>
/* Implemented in Rust (OS CSPRNG via getrandom). Returns 0 on success. */
int nq_randombytes(uint8_t *out, size_t len);
/* Runtime CPU dispatch, same policy as AWS-LC: AVX2 && BMI2 (OS-enabled). */
static inline int nq_cpu_avx2_bmi2(void)
{
  return __builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi2");
}
#endif
#endif

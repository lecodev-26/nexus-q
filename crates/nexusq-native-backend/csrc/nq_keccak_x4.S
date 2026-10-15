/* s2n-bignum AVX2 4-way Keccak-f1600 (vendor/s2n-bignum), renamed and hidden.
 * Selected at runtime only when AVX2 is available (see nq_fips202_x86_64_*.h). */
#if defined(__x86_64__) && defined(__linux__) && !defined(NQ_PORTABLE_ONLY) && !defined(NQ_UPSTREAM_X4_KECCAK)
#define S2N_BN_HIDE_SYMBOLS
#define sha3_keccak4_f1600_alt nq_sha3_keccak4_f1600_alt
#include "x86_att/sha3/sha3_keccak4_f1600_alt.S"
#endif
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

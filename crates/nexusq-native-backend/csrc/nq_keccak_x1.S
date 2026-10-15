/* s2n-bignum scalar Keccak-f1600 (vendor/s2n-bignum), renamed and hidden. */
#if defined(__x86_64__) && defined(__linux__) && !defined(NQ_PORTABLE_ONLY) && !defined(NQ_NO_S2N_KECCAK)
#define S2N_BN_HIDE_SYMBOLS
#define sha3_keccak_f1600 nq_sha3_keccak_f1600
#include "x86_att/sha3/sha3_keccak_f1600.S"
#endif
#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

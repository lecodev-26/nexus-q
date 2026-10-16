#include "mldsa_native.c"

/* ABI guard, see nq_mlkem_all.c. */
typedef int (*nq_dkp_t)(uint8_t *, uint8_t *);
typedef int (*nq_dkpi_t)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*nq_dsig_t)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
typedef int (*nq_dsigi_t)(uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *, int);
typedef int (*nq_dver_t)(const uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
const nq_dkp_t nq_abi_d1 = nq_mldsa65_keypair;
const nq_dkpi_t nq_abi_d2 = nq_mldsa65_keypair_internal;
const nq_dsig_t nq_abi_d3 = nq_mldsa65_signature;
const nq_dsigi_t nq_abi_d4 = nq_mldsa65_signature_internal;
const nq_dver_t nq_abi_d5 = nq_mldsa65_verify;

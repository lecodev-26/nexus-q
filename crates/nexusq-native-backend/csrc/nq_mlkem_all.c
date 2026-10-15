/* ML-KEM-768 and ML-KEM-1024 in one translation unit (monolithic build). */
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED 1
#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem_native.c"
#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED
#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#undef MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET

/* ABI guard: the Rust FFI declarations in src/lib.rs must match these exact
 * prototypes. Built with -Werror=incompatible-pointer-types, so any upstream
 * signature drift breaks the build instead of corrupting memory at runtime. */
typedef int (*nq_kp_t)(uint8_t *, uint8_t *);
typedef int (*nq_kpd_t)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*nq_enc_t)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*nq_encd_t)(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
typedef int (*nq_dec_t)(uint8_t *, const uint8_t *, const uint8_t *);
const nq_kp_t nq_abi_k1[] = {nq_mlkem768_keypair, nq_mlkem1024_keypair};
const nq_kpd_t nq_abi_k2[] = {nq_mlkem768_keypair_derand, nq_mlkem1024_keypair_derand};
const nq_enc_t nq_abi_k3[] = {nq_mlkem768_enc, nq_mlkem1024_enc};
const nq_encd_t nq_abi_k4[] = {nq_mlkem768_enc_derand, nq_mlkem1024_enc_derand};
const nq_dec_t nq_abi_k5[] = {nq_mlkem768_dec, nq_mlkem1024_dec};

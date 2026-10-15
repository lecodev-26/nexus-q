/* Constant-time check (ctgrind style) of the exact NEXUS-Q native build:
 * every byte from the RNG and every secret key is marked "undefined" for
 * valgrind memcheck; any branch or memory index depending on it is an error.
 * Public outputs are declassified by the libraries' own CT-testing hooks. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <valgrind/memcheck.h>
int nq_randombytes(uint8_t *out, size_t len) {
  size_t off = 0;
  while (off < len) { ssize_t r = getrandom(out + off, len - off, 0); if (r <= 0) return -1; off += (size_t)r; }
  VALGRIND_MAKE_MEM_UNDEFINED(out, len);
  return 0;
}
int nq_mlkem768_keypair(uint8_t*, uint8_t*); int nq_mlkem768_enc(uint8_t*, uint8_t*, const uint8_t*); int nq_mlkem768_dec(uint8_t*, const uint8_t*, const uint8_t*);
int nq_mlkem1024_keypair(uint8_t*, uint8_t*); int nq_mlkem1024_enc(uint8_t*, uint8_t*, const uint8_t*); int nq_mlkem1024_dec(uint8_t*, const uint8_t*, const uint8_t*);
int nq_mldsa65_keypair(uint8_t*, uint8_t*);
int nq_mldsa65_signature(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
int nq_mldsa65_verify(const uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
#define CHECK(x) do { int rc_ = (x); VALGRIND_MAKE_MEM_DEFINED(&rc_, sizeof rc_); if (rc_) { printf("FAIL %s rc=%d\n", #x, rc_); return 1; } } while (0)
#define KEM(L, PK, SK, CT) do { \
  static uint8_t pk[PK], sk[SK], ct[CT], ss[32], ss2[32]; \
  CHECK(nq_mlkem##L##_keypair(pk, sk)); \
  VALGRIND_MAKE_MEM_DEFINED(pk, PK); \
  CHECK(nq_mlkem##L##_enc(ct, ss, pk)); \
  VALGRIND_MAKE_MEM_DEFINED(ct, CT); \
  VALGRIND_MAKE_MEM_UNDEFINED(sk, SK); /* decapsulation key is secret */ \
  CHECK(nq_mlkem##L##_dec(ss2, ct, sk)); \
  ct[5] ^= 1; /* implicit-rejection path must also be constant time */ \
  CHECK(nq_mlkem##L##_dec(ss2, ct, sk)); \
} while (0)
int main(void) {
  for (int i = 0; i < 3; i++) { KEM(768, 1184, 2400, 1088); KEM(1024, 1568, 3168, 1568); }
  static uint8_t pk[1952], sk[4032], sig[3309];
  const uint8_t msg[] = "nexusq-pqc-arena-v1";
  for (int i = 0; i < 3; i++) {
    CHECK(nq_mldsa65_keypair(pk, sk));
    VALGRIND_MAKE_MEM_DEFINED(pk, sizeof pk);
    VALGRIND_MAKE_MEM_UNDEFINED(sk, sizeof sk); /* signing key is secret */
    CHECK(nq_mldsa65_signature(sig, msg, sizeof msg - 1, NULL, 0, sk));
    VALGRIND_MAKE_MEM_DEFINED(sig, sizeof sig);
    CHECK(nq_mldsa65_verify(sig, msg, sizeof msg - 1, NULL, 0, pk));
  }
  printf("CT harness completed\n");
  return 0;
}

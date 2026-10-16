/* Diagnostic only (not a gate input): AWS-LC and the NEXUS-Q native backend
 * linked into ONE process, called alternately on every iteration, so that both
 * see the same CPU, frequency, cache and noisy-neighbour conditions.
 * Compares the libraries' internal entry points directly; no EVP layer, no Rust.
 *   inproc_ab [N] [op]   op = all | kem768-decaps | ... (for perf record)
 *   NQ_AB_IMPL=aws|nq    restrict to one implementation (for perf record)  */
/* Return conventions: AWS-LC ml_kem_xxx return 0 on success (ML_KEM_SUCCESS);
 * AWS-LC ml_dsa_xxx return 1 on success (ML_DSA_SUCCESS); mlkem-native and
 * mldsa-native return 0 on success. run() returns 0 on success. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>

int nq_randombytes(uint8_t *out, size_t len) {
  size_t off = 0;
  while (off < len) { ssize_t r = getrandom(out + off, len - off, 0); if (r <= 0) return -1; off += (size_t)r; }
  return 0;
}
/* NEXUS-Q native backend */
int nq_mlkem768_keypair(uint8_t*, uint8_t*); int nq_mlkem768_keypair_derand(uint8_t*, uint8_t*, const uint8_t*);
int nq_mlkem768_enc(uint8_t*, uint8_t*, const uint8_t*); int nq_mlkem768_enc_derand(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*);
int nq_mlkem768_dec(uint8_t*, const uint8_t*, const uint8_t*);
int nq_mlkem1024_keypair(uint8_t*, uint8_t*); int nq_mlkem1024_enc(uint8_t*, uint8_t*, const uint8_t*); int nq_mlkem1024_dec(uint8_t*, const uint8_t*, const uint8_t*);
int nq_mlkem1024_keypair_derand(uint8_t*, uint8_t*, const uint8_t*); int nq_mlkem1024_enc_derand(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*);
int nq_mldsa65_keypair(uint8_t*, uint8_t*);
int nq_mldsa65_signature(uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
int nq_mldsa65_verify(const uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
/* AWS-LC internal API (crypto/fipsmodule/ml_kem/ml_kem.h, ml_dsa/ml_dsa.h) */
int ml_kem_768_keypair(uint8_t*, size_t*, uint8_t*, size_t*);
int ml_kem_768_keypair_deterministic_no_self_test(uint8_t*, size_t*, uint8_t*, size_t*, const uint8_t*);
int ml_kem_768_encapsulate(uint8_t*, size_t*, uint8_t*, size_t*, const uint8_t*);
int ml_kem_768_encapsulate_deterministic_no_self_test(uint8_t*, size_t*, uint8_t*, size_t*, const uint8_t*, const uint8_t*);
int ml_kem_768_decapsulate_no_self_test(uint8_t*, size_t*, const uint8_t*, const uint8_t*);
int ml_kem_1024_keypair(uint8_t*, size_t*, uint8_t*, size_t*);
int ml_kem_1024_keypair_deterministic_no_self_test(uint8_t*, size_t*, uint8_t*, size_t*, const uint8_t*);
int ml_kem_1024_encapsulate(uint8_t*, size_t*, uint8_t*, size_t*, const uint8_t*);
int ml_kem_1024_encapsulate_deterministic_no_self_test(uint8_t*, size_t*, uint8_t*, size_t*, const uint8_t*, const uint8_t*);
int ml_kem_1024_decapsulate_no_self_test(uint8_t*, size_t*, const uint8_t*, const uint8_t*);
int ml_dsa_65_keypair(uint8_t*, uint8_t*, uint8_t*);
int ml_dsa_65_sign(const uint8_t*, uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t);
int ml_dsa_65_verify(const uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);

static uint8_t pk[2][1952], sk[2][4032], ct[2][1568], ss[2][32], sig[2][3309], seed[64], coins[32];
static const uint8_t msg[] = "nexusq-pqc-arena-v1";
static size_t L1, L2, L3, L4;
#define LEN(x) (L1 = sizeof pk[0], L2 = sizeof sk[0], L3 = sizeof ct[0], L4 = 32, (void)0)

static int run(const char *op, int impl) { /* impl 0 = AWS-LC, 1 = NEXUS-Q */
  LEN();
  if (!strcmp(op, "kem768-keygen")) return impl ? nq_mlkem768_keypair(pk[1], sk[1]) : ml_kem_768_keypair(pk[0], &L1, sk[0], &L2);
  if (!strcmp(op, "kem768-keygen-derand")) return impl ? nq_mlkem768_keypair_derand(pk[1], sk[1], seed) : ml_kem_768_keypair_deterministic_no_self_test(pk[0], &L1, sk[0], &L2, seed);
  if (!strcmp(op, "kem768-encaps")) return impl ? nq_mlkem768_enc(ct[1], ss[1], pk[1]) : ml_kem_768_encapsulate(ct[0], &L3, ss[0], &L4, pk[0]);
  if (!strcmp(op, "kem768-encaps-derand")) return impl ? nq_mlkem768_enc_derand(ct[1], ss[1], pk[1], coins) : ml_kem_768_encapsulate_deterministic_no_self_test(ct[0], &L3, ss[0], &L4, pk[0], coins);
  if (!strcmp(op, "kem768-decaps")) return impl ? nq_mlkem768_dec(ss[1], ct[1], sk[1]) : ml_kem_768_decapsulate_no_self_test(ss[0], &L4, ct[0], sk[0]);
  if (!strcmp(op, "kem1024-keygen")) return impl ? nq_mlkem1024_keypair(pk[1], sk[1]) : ml_kem_1024_keypair(pk[0], &L1, sk[0], &L2);
  if (!strcmp(op, "kem1024-keygen-derand")) return impl ? nq_mlkem1024_keypair_derand(pk[1], sk[1], seed) : ml_kem_1024_keypair_deterministic_no_self_test(pk[0], &L1, sk[0], &L2, seed);
  if (!strcmp(op, "kem1024-encaps")) return impl ? nq_mlkem1024_enc(ct[1], ss[1], pk[1]) : ml_kem_1024_encapsulate(ct[0], &L3, ss[0], &L4, pk[0]);
  if (!strcmp(op, "kem1024-encaps-derand")) return impl ? nq_mlkem1024_enc_derand(ct[1], ss[1], pk[1], coins) : ml_kem_1024_encapsulate_deterministic_no_self_test(ct[0], &L3, ss[0], &L4, pk[0], coins);
  if (!strcmp(op, "kem1024-decaps")) return impl ? nq_mlkem1024_dec(ss[1], ct[1], sk[1]) : ml_kem_1024_decapsulate_no_self_test(ss[0], &L4, ct[0], sk[0]);
  if (!strcmp(op, "dsa65-keygen")) return impl ? nq_mldsa65_keypair(pk[1], sk[1]) : !ml_dsa_65_keypair(pk[0], sk[0], seed);
  if (!strcmp(op, "dsa65-sign")) { size_t sl = sizeof sig[0]; return impl ? nq_mldsa65_signature(sig[1], msg, sizeof msg - 1, NULL, 0, sk[1]) : !ml_dsa_65_sign(sk[0], sig[0], &sl, msg, sizeof msg - 1, NULL, 0); }
  if (!strcmp(op, "dsa65-verify")) return impl ? nq_mldsa65_verify(sig[1], msg, sizeof msg - 1, NULL, 0, pk[1]) : !ml_dsa_65_verify(pk[0], sig[0], 3309, msg, sizeof msg - 1, NULL, 0);
  fprintf(stderr, "unknown op %s\n", op); exit(64);
}
static void setup(const char *op) {
  int kem1024 = !!strstr(op, "kem1024"), dsa = !!strstr(op, "dsa65");
  for (int i = 0; i < 2; i++) {
    if (dsa) { if (run("dsa65-keygen", i) || run("dsa65-sign", i)) { fprintf(stderr, "setup failed\n"); exit(1); } }
    else if (run(kem1024 ? "kem1024-keygen" : "kem768-keygen", i) || run(kem1024 ? "kem1024-encaps" : "kem768-encaps", i)) { fprintf(stderr, "setup failed\n"); exit(1); }
  }
}
static int cmp(const void *a, const void *b) { uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return x < y ? -1 : x > y; }
static uint64_t now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec; }

int main(int argc, char **argv) {
  int n = argc > 1 ? atoi(argv[1]) : 5000;
  const char *only = argc > 2 ? argv[2] : "all";
  const char *impl_env = getenv("NQ_AB_IMPL");
  int only_impl = impl_env ? (strcmp(impl_env, "nq") == 0) : -1;
  const char *ops[] = {"kem768-keygen", "kem768-keygen-derand", "kem768-encaps", "kem768-encaps-derand", "kem768-decaps",
                       "kem1024-keygen", "kem1024-keygen-derand", "kem1024-encaps", "kem1024-encaps-derand", "kem1024-decaps",
                       "dsa65-keygen", "dsa65-sign", "dsa65-verify"};
  if (nq_randombytes(seed, sizeof seed) || nq_randombytes(coins, sizeof coins)) return 1;
  uint64_t *t[2] = {malloc(sizeof(uint64_t) * n), malloc(sizeof(uint64_t) * n)};
  printf("op\taws_med_ns\tnq_med_ns\tratio_med\taws_p95_ns\tnq_p95_ns\tratio_p95\n");
  for (size_t k = 0; k < sizeof ops / sizeof ops[0]; k++) {
    const char *op = ops[k];
    if (strcmp(only, "all") && strcmp(only, op)) continue;
    setup(op);
    for (int w = 0; w < 200; w++) { run(op, 0); run(op, 1); }
    for (int i = 0; i < n; i++) {
      for (int j = 0; j < 2; j++) {
        int impl = (i & 1) ? 1 - j : j; /* alternate which implementation goes first */
        if (only_impl >= 0 && impl != only_impl) continue;
        uint64_t a = now();
        if (run(op, impl)) { fprintf(stderr, "%s failed\n", op); return 1; }
        t[impl][i] = now() - a;
      }
    }
    if (only_impl >= 0) continue;
    qsort(t[0], n, 8, cmp); qsort(t[1], n, 8, cmp);
    size_t p = (size_t)((n * 95 + 99) / 100) - 1;
    printf("%s\t%lu\t%lu\t%.3f\t%lu\t%lu\t%.3f\n", op, t[0][n / 2], t[1][n / 2], (double)t[1][n / 2] / t[0][n / 2], t[0][p], t[1][p], (double)t[1][p] / t[0][p]);
  }
  return 0;
}

#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <mlkem_native.h>
#include <mldsa_native.h>

#define ITERATIONS 20
#define WARMUPS 3
#define MSG "nexusq-arena"
#define MSG_LEN (sizeof(MSG) - 1)

static uint64_t now_ns(clockid_t id) {
    struct timespec ts;
    if (clock_gettime(id, &ts) != 0) exit(2);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void env_string(const char *name, const char *fallback, char *dst, size_t n) {
    const char *v = getenv(name);
    snprintf(dst, n, "%s", v && *v ? v : fallback);
}

static void json_size(int value, char *buf, size_t n) {
    if (value < 0) snprintf(buf, n, "null");
    else snprintf(buf, n, "%d", value);
}

static void emit(const char *run_id, const char *impl_ver, const char *commit,
                 const char *alg, const char *param, const char *op,
                 double latency, int pk, int sk, int ct, int sig) {
    char target[128], os[128], cpu[256], compiler[128], compver[256], opt[64];
    char jpk[32], jsk[32], jct[32], jsig[32];
    env_string("ARENA_TARGET", "x86_64-linux-gnu", target, sizeof(target));
    env_string("ARENA_OS", "unknown", os, sizeof(os));
    env_string("ARENA_CPU", "unknown", cpu, sizeof(cpu));
    env_string("ARENA_COMPILER", "cc", compiler, sizeof(compiler));
    env_string("ARENA_COMPILER_VERSION", __VERSION__, compver, sizeof(compver));
    env_string("ARENA_OPT", "release", opt, sizeof(opt));
    json_size(pk, jpk, sizeof(jpk)); json_size(sk, jsk, sizeof(jsk));
    json_size(ct, jct, sizeof(jct)); json_size(sig, jsig, sizeof(jsig));
    printf("{\"schema_version\":1,\"run_id\":\"%s\",\"implementation\":{\"id\":\"pq-code-package\",\"version\":\"%s\",\"commit\":\"%s\"},"
           "\"algorithm\":{\"id\":\"%s\",\"parameter_set\":\"%s\"},\"operation\":\"%s\","
           "\"environment\":{\"target\":\"%s\",\"os\":\"%s\",\"cpu\":\"%s\",\"cpu_features\":[],"
           "\"compiler\":\"%s\",\"compiler_version\":\"%s\",\"optimization\":\"%s\",\"harness_version\":\"arena-v1\"},"
           "\"measurement\":{\"iterations\":%d,\"warmups\":%d,\"latency_ns\":%.3f,\"throughput_ops_s\":%.6f,"
           "\"memory_bytes\":null,\"measurement_method\":\"monotonic-clock-average\"},"
           "\"sizes\":{\"public_key_bytes\":%s,\"secret_key_bytes\":%s,\"ciphertext_bytes\":%s,\"signature_bytes\":%s}}\n",
           run_id, impl_ver, commit, alg, param, op, target, os, cpu, compiler, compver, opt,
           ITERATIONS, WARMUPS, latency, 1e9 / latency, jpk, jsk, jct, jsig);
}

typedef struct { uint8_t *pk, *sk, *ct, *ss; } kem_ctx;
static int kem_keygen(void *v) { kem_ctx *c = v; return mlkem_keypair(c->pk, c->sk); }
static int kem_encaps(void *v) { kem_ctx *c = v; return mlkem_enc(c->ct, c->ss, c->pk); }
static int kem_decaps(void *v) { kem_ctx *c = v; return mlkem_dec(c->ss, c->ct, c->sk); }

typedef struct { uint8_t *pk, *sk, *sig; size_t siglen; } dsa_ctx;
static int dsa_keygen(void *v) { dsa_ctx *c = v; return crypto_sign_keypair(c->pk, c->sk); }
static int dsa_sign(void *v) {
    dsa_ctx *c = v;
    return crypto_sign_signature(c->sig, &c->siglen, (const uint8_t *)MSG, MSG_LEN,
                                 NULL, 0, c->sk);
}
static int dsa_verify(void *v) {
    dsa_ctx *c = v;
    return crypto_sign_verify(c->sig, c->siglen, (const uint8_t *)MSG, MSG_LEN,
                              NULL, 0, c->pk);
}

static double bench(int (*fn)(void *), void *arg) {
    for (int i = 0; i < WARMUPS; ++i) if (fn(arg) != 0) exit(3);
    uint64_t start = now_ns(CLOCK_MONOTONIC);
    for (int i = 0; i < ITERATIONS; ++i) if (fn(arg) != 0) exit(3);
    return (double)(now_ns(CLOCK_MONOTONIC) - start) / ITERATIONS;
}

int main(void) {
    uint8_t kem_pk[MLKEM768_PUBLICKEYBYTES], kem_sk[MLKEM768_SECRETKEYBYTES];
    uint8_t kem_ct[MLKEM768_CIPHERTEXTBYTES], kem_ss[MLKEM_BYTES];
    uint8_t dsa_pk[MLDSA65_PUBLICKEYBYTES], dsa_sk[MLDSA65_SECRETKEYBYTES];
    uint8_t dsa_sig[MLDSA65_BYTES];
    kem_ctx k = {kem_pk, kem_sk, kem_ct, kem_ss};
    dsa_ctx d = {dsa_pk, dsa_sk, dsa_sig, MLDSA65_BYTES};

    const char *ver = getenv("PQCP_VERSION");
    const char *commit = getenv("PQCP_COMMIT");
    if (!ver) ver = "mlkem-native-v2.0.0 + mldsa-native-v1.0.0-beta2";
    if (!commit) commit = "mlkem-native@d1b2fe782888bdb761a50336012923180be7f502;mldsa-native@9b0ee84f4cf399043eca59eca4e5f8531ca1d61b";

    emit("pqcp-mlkem-768-keygen", ver, commit, "ml-kem", "768", "keygen",
         bench(kem_keygen, &k), MLKEM768_PUBLICKEYBYTES, MLKEM768_SECRETKEYBYTES, MLKEM768_CIPHERTEXTBYTES, -1);
    emit("pqcp-mlkem-768-encaps", ver, commit, "ml-kem", "768", "encaps",
         bench(kem_encaps, &k), MLKEM768_PUBLICKEYBYTES, MLKEM768_SECRETKEYBYTES, MLKEM768_CIPHERTEXTBYTES, -1);
    emit("pqcp-mlkem-768-decaps", ver, commit, "ml-kem", "768", "decaps",
         bench(kem_decaps, &k), MLKEM768_PUBLICKEYBYTES, MLKEM768_SECRETKEYBYTES, MLKEM768_CIPHERTEXTBYTES, -1);

    emit("pqcp-ml-dsa-65-keygen", ver, commit, "ml-dsa", "65", "keygen",
         bench(dsa_keygen, &d), MLDSA65_PUBLICKEYBYTES, MLDSA65_SECRETKEYBYTES, -1, MLDSA65_BYTES);
    if (dsa_sign(&d) != 0) exit(4);
    emit("pqcp-ml-dsa-65-sign", ver, commit, "ml-dsa", "65", "sign",
         bench(dsa_sign, &d), MLDSA65_PUBLICKEYBYTES, MLDSA65_SECRETKEYBYTES, -1, MLDSA65_BYTES);
    emit("pqcp-ml-dsa-65-verify", ver, commit, "ml-dsa", "65", "verify",
         bench(dsa_verify, &d), MLDSA65_PUBLICKEYBYTES, MLDSA65_SECRETKEYBYTES, -1, MLDSA65_BYTES);
    return 0;
}

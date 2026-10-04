#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/utsname.h>

#define ITERATIONS 20
#define WARMUPS 3
#define LIBOQS_VERSION "0.16.0"
#ifndef LIBOQS_COMMIT
#define LIBOQS_COMMIT "unknown"
#endif

static double elapsed_ns(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) * 1e9 +
           (double)(end.tv_nsec - start.tv_nsec);
}

static const char *env_or(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return value && *value ? value : fallback;
}

static void environment(char *target, size_t target_len,
                        char *os, size_t os_len,
                        char *cpu, size_t cpu_len) {
    const char *target_env = getenv("ARENA_TARGET");
    const char *os_env = getenv("ARENA_OS");
    const char *cpu_env = getenv("ARENA_CPU");
    struct utsname u;
    if (target_env && *target_env && os_env && *os_env && cpu_env && *cpu_env) {
        snprintf(target, target_len, "%s", target_env);
        snprintf(os, os_len, "%s", os_env);
        snprintf(cpu, cpu_len, "%s", cpu_env);
    } else if (uname(&u) == 0) {
        snprintf(target, target_len, "%s-%s", u.machine, u.sysname);
        snprintf(os, os_len, "%s", u.sysname);
        snprintf(cpu, cpu_len, "%s", u.machine);
    } else {
        snprintf(target, target_len, "%s", env_or("ARENA_TARGET", "unknown"));
        snprintf(os, os_len, "%s", env_or("ARENA_OS", "unknown"));
        snprintf(cpu, cpu_len, "%s", env_or("ARENA_CPU", "unknown"));
    }
}

static void emit(const char *alg, const char *param, const char *op,
                 double latency_ns, size_t pk, size_t sk,
                 size_t ct, size_t sig, int has_ct, int has_sig) {
    char target[128], os[64], cpu[128];
    environment(target, sizeof(target), os, sizeof(os), cpu, sizeof(cpu));
    const char *features = env_or("ARENA_CPU_FEATURES", "");
    const char *optimization = env_or("ARENA_OPT", "unknown");
    struct timespec timestamp;
    clock_gettime(CLOCK_REALTIME, &timestamp);
    unsigned long long timestamp_ns =
        (unsigned long long)timestamp.tv_sec * 1000000000ULL +
        (unsigned long long)timestamp.tv_nsec;
    char ct_json[32], sig_json[32];
    snprintf(ct_json, sizeof(ct_json), has_ct ? "%zu" : "null", ct);
    snprintf(sig_json, sizeof(sig_json), has_sig ? "%zu" : "null", sig);
    printf(
        "{\"schema_version\":1,\"run_id\":\"liboqs-%s-%s-%s\","
        "\"implementation\":{\"id\":\"liboqs\",\"version\":\"%s\",\"commit\":\"%s\"},"
        "\"algorithm\":{\"id\":\"%s\",\"parameter_set\":\"%s\"},"
        "\"operation\":\"%s\","
        "\"environment\":{\"target\":\"%s\",\"os\":\"%s\",\"cpu\":\"%s\","
        "\"cpu_features\":[%s],\"compiler\":\"cc\",\"compiler_version\":\"%s\","
        "\"optimization\":\"%s\",\"harness_version\":\"arena-v1\"},"
        "\"measurement\":{\"iterations\":%d,\"warmups\":%d,\"measurement_timestamp_unix_ns\":%llu,\"latency_ns\":%.3f,"
        "\"throughput_ops_s\":%.6f,\"memory_bytes\":null,"
        "\"measurement_method\":\"clock_gettime(CLOCK_MONOTONIC) mean wall-clock latency\"},"
        "\"sizes\":{\"public_key_bytes\":%zu,\"secret_key_bytes\":%zu,"
        "\"ciphertext_bytes\":%s,\"signature_bytes\":%s}}\n",
        alg, param, op, LIBOQS_VERSION, LIBOQS_COMMIT,
        alg, param, op, target, os, cpu, features, __VERSION__, optimization,
        ITERATIONS, WARMUPS, timestamp_ns, latency_ns, 1e9 / latency_ns, pk, sk,
        ct_json, sig_json);
}

static int kem(const char *name, const char *param) {
    OQS_KEM *k = OQS_KEM_new(name);
    if (!k) return 1;

    uint8_t *pk = malloc(k->length_public_key);
    uint8_t *sk = malloc(k->length_secret_key);
    uint8_t *ct = malloc(k->length_ciphertext);
    uint8_t *ss = malloc(k->length_shared_secret);
    if (!pk || !sk || !ct || !ss) {
        free(pk); free(sk); free(ct); free(ss); OQS_KEM_free(k); return 2;
    }

    struct timespec a, b;
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_KEM_keypair(k, pk, sk) != OQS_SUCCESS) return 3;
    }
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < ITERATIONS; i++) {
        if (OQS_KEM_keypair(k, pk, sk) != OQS_SUCCESS) return 3;
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    emit("ml-kem", param, "keygen", elapsed_ns(a, b) / ITERATIONS,
         k->length_public_key, k->length_secret_key, k->length_ciphertext, 0, 1, 0);

    if (OQS_KEM_keypair(k, pk, sk) != OQS_SUCCESS) return 4;
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_KEM_encaps(k, ct, ss, pk) != OQS_SUCCESS) return 5;
    }
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < ITERATIONS; i++) {
        if (OQS_KEM_encaps(k, ct, ss, pk) != OQS_SUCCESS) return 5;
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    emit("ml-kem", param, "encaps", elapsed_ns(a, b) / ITERATIONS,
         k->length_public_key, k->length_secret_key, k->length_ciphertext, 0, 1, 0);

    if (OQS_KEM_encaps(k, ct, ss, pk) != OQS_SUCCESS) return 6;
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_KEM_decaps(k, ss, ct, sk) != OQS_SUCCESS) return 7;
    }
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < ITERATIONS; i++) {
        if (OQS_KEM_decaps(k, ss, ct, sk) != OQS_SUCCESS) return 7;
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    emit("ml-kem", param, "decaps", elapsed_ns(a, b) / ITERATIONS,
         k->length_public_key, k->length_secret_key, k->length_ciphertext, 0, 1, 0);

    free(pk); free(sk); free(ct); free(ss); OQS_KEM_free(k);
    return 0;
}

static int sig(const char *name, const char *param) {
    OQS_SIG *s = OQS_SIG_new(name);
    if (!s) return 1;

    uint8_t *pk = malloc(s->length_public_key);
    uint8_t *sk = malloc(s->length_secret_key);
    uint8_t *buf = malloc(s->length_signature);
    if (!pk || !sk || !buf) {
        free(pk); free(sk); free(buf); OQS_SIG_free(s); return 2;
    }

    const uint8_t msg[] = "nexusq-pqc-arena-v1";
    size_t sl = 0;
    struct timespec a, b;

    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_SIG_keypair(s, pk, sk) != OQS_SUCCESS) return 3;
    }
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < ITERATIONS; i++) {
        if (OQS_SIG_keypair(s, pk, sk) != OQS_SUCCESS) return 3;
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    emit("ml-dsa", param, "keygen", elapsed_ns(a, b) / ITERATIONS,
         s->length_public_key, s->length_secret_key, 0, s->length_signature, 0, 1);

    if (OQS_SIG_keypair(s, pk, sk) != OQS_SUCCESS) return 4;
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_SIG_sign(s, buf, &sl, msg, sizeof(msg) - 1, sk) != OQS_SUCCESS) return 5;
    }
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < ITERATIONS; i++) {
        if (OQS_SIG_sign(s, buf, &sl, msg, sizeof(msg) - 1, sk) != OQS_SUCCESS) return 5;
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    emit("ml-dsa", param, "sign", elapsed_ns(a, b) / ITERATIONS,
         s->length_public_key, s->length_secret_key, 0, sl, 0, 1);

    if (OQS_SIG_sign(s, buf, &sl, msg, sizeof(msg) - 1, sk) != OQS_SUCCESS) return 6;
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_SIG_verify(s, msg, sizeof(msg) - 1, buf, sl, pk) != OQS_SUCCESS) return 7;
    }
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < ITERATIONS; i++) {
        if (OQS_SIG_verify(s, msg, sizeof(msg) - 1, buf, sl, pk) != OQS_SUCCESS) return 7;
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    emit("ml-dsa", param, "verify", elapsed_ns(a, b) / ITERATIONS,
         s->length_public_key, s->length_secret_key, 0, sl, 0, 1);

    free(pk); free(sk); free(buf); OQS_SIG_free(s);
    return 0;
}

int main(void) {
    OQS_init();
    int rc = kem("ML-KEM-768", "768");
    rc |= kem("ML-KEM-1024", "1024");
    rc |= sig("ML-DSA-65", "65");
    OQS_destroy();
    return rc;
}

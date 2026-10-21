#define _POSIX_C_SOURCE 200809L
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <sys/utsname.h>

#define ITERATIONS 1000
#define WARMUPS 100
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
        snprintf(target, target_len, "%.60s-%.60s", u.machine, u.sysname);
        snprintf(os, os_len, "%.63s", u.sysname);
        snprintf(cpu, cpu_len, "%s", u.machine);
    } else {
        snprintf(target, target_len, "%s", env_or("ARENA_TARGET", "unknown"));
        snprintf(os, os_len, "%s", env_or("ARENA_OS", "unknown"));
        snprintf(cpu, cpu_len, "%s", env_or("ARENA_CPU", "unknown"));
    }
}

static int compare_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void format_cpu_features(char *out, size_t out_len) {
    const char *raw = env_or("ARENA_CPU_FEATURES", "");
    size_t used = 0;
    if (out_len == 0) return;
    out[used++] = '[';
    while (*raw && used + 4 < out_len) {
        const char *end = strchr(raw, ',');
        size_t len = end ? (size_t)(end - raw) : strlen(raw);
        if (len > 0) {
            int written = snprintf(out + used, out_len - used, "%s\"%.*s\"", used > 1 ? "," : "", (int)len, raw);
            if (written < 0 || (size_t)written >= out_len - used) break;
            used += (size_t)written;
        }
        if (!end) break;
        raw = end + 1;
    }
    if (used < out_len - 1) { out[used++] = ']'; out[used] = '\0'; }
    else out[out_len - 1] = '\0';
}

static void emit(const char *alg, const char *param, const char *op,
                 const uint64_t *samples, size_t sample_count, size_t pk, size_t sk,
                 size_t ct, size_t sig, int has_ct, int has_sig) {
    char target[128], os[64], cpu[128];
    uint64_t sorted[ITERATIONS];
    if (sample_count == 0 || sample_count > ITERATIONS) abort();
    memcpy(sorted, samples, sample_count * sizeof(uint64_t));
    qsort(sorted, sample_count, sizeof(uint64_t), compare_u64);
    uint64_t median = sample_count % 2 ? sorted[sample_count / 2] : sorted[sample_count / 2 - 1] + (sorted[sample_count / 2] - sorted[sample_count / 2 - 1]) / 2;
    uint64_t p95 = sorted[(sample_count * 95 + 99) / 100 - 1];
    environment(target, sizeof(target), os, sizeof(os), cpu, sizeof(cpu));
    char features[8192];
    format_cpu_features(features, sizeof(features));
    const char *optimization = env_or("ARENA_OPT", "unknown");
    struct timespec timestamp;
    clock_gettime(CLOCK_REALTIME, &timestamp);
    unsigned long long timestamp_ns = (unsigned long long)timestamp.tv_sec * 1000000000ULL + (unsigned long long)timestamp.tv_nsec;
    char ct_json[32], sig_json[32];
    snprintf(ct_json, sizeof(ct_json), has_ct ? "%zu" : "null", ct);
    snprintf(sig_json, sizeof(sig_json), has_sig ? "%zu" : "null", sig);
    printf("{\"schema_version\":1,\"run_id\":\"liboqs-%s-%s-%s\","
           "\"implementation\":{\"id\":\"liboqs\",\"version\":\"%s\",\"commit\":\"%s\"},"
           "\"algorithm\":{\"id\":\"%s\",\"parameter_set\":\"%s\"},\"operation\":\"%s\","
           "\"environment\":{\"target\":\"%s\",\"os\":\"%s\",\"cpu\":\"%s\",\"cpu_features\":%s,"
           "\"compiler\":\"cc\",\"compiler_version\":\"%s\",\"optimization\":\"%s\",\"harness_version\":\"arena-v2\"},"
           "\"measurement\":{\"iterations\":%zu,\"warmups\":%d,\"measurement_timestamp_unix_ns\":%llu,"
           "\"latency_ns\":%llu,\"median_ns\":%llu,\"p95_ns\":%llu,\"samples_ns\":[",
           alg, param, op, LIBOQS_VERSION, LIBOQS_COMMIT, alg, param, op, target, os, cpu, features,
           __VERSION__, optimization, sample_count, WARMUPS, timestamp_ns,
           (unsigned long long)median, (unsigned long long)median, (unsigned long long)p95);
    for (size_t i = 0; i < sample_count; i++) printf("%s%llu", i ? "," : "", (unsigned long long)samples[i]);
    printf("],\"throughput_ops_s\":%.6f,\"memory_bytes\":null,\"measurement_scope\":\"reference_implementation_operation\","
           "\"comparison_contract\":\"fips_operation_v1\",\"measurement_method\":\"clock_gettime(CLOCK_MONOTONIC) per-operation raw samples\"},"
           "\"sizes\":{\"public_key_bytes\":%zu,\"secret_key_bytes\":%zu,\"ciphertext_bytes\":%s,\"signature_bytes\":%s}}\n",
           1e9 / (double)median, pk, sk, ct_json, sig_json);
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
    uint64_t samples[ITERATIONS];
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_KEM_keypair(k, pk, sk) != OQS_SUCCESS) return 3;
    }
    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &a);
        if (OQS_KEM_keypair(k, pk, sk) != OQS_SUCCESS) return 3;
        clock_gettime(CLOCK_MONOTONIC, &b);
        samples[i] = (uint64_t)elapsed_ns(a, b);
        if (samples[i] == 0) samples[i] = 1;
    }
    emit("ml-kem", param, "keygen", samples, ITERATIONS,
         k->length_public_key, k->length_secret_key, k->length_ciphertext, 0, 1, 0);

    if (OQS_KEM_keypair(k, pk, sk) != OQS_SUCCESS) return 4;
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_KEM_encaps(k, ct, ss, pk) != OQS_SUCCESS) return 5;
    }
    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &a);
        if (OQS_KEM_encaps(k, ct, ss, pk) != OQS_SUCCESS) return 5;
        clock_gettime(CLOCK_MONOTONIC, &b);
        samples[i] = (uint64_t)elapsed_ns(a, b);
        if (samples[i] == 0) samples[i] = 1;
    }
    emit("ml-kem", param, "encaps", samples, ITERATIONS,
         k->length_public_key, k->length_secret_key, k->length_ciphertext, 0, 1, 0);

    if (OQS_KEM_encaps(k, ct, ss, pk) != OQS_SUCCESS) return 6;
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_KEM_decaps(k, ss, ct, sk) != OQS_SUCCESS) return 7;
    }
    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &a);
        if (OQS_KEM_decaps(k, ss, ct, sk) != OQS_SUCCESS) return 7;
        clock_gettime(CLOCK_MONOTONIC, &b);
        samples[i] = (uint64_t)elapsed_ns(a, b);
        if (samples[i] == 0) samples[i] = 1;
    }
    emit("ml-kem", param, "decaps", samples, ITERATIONS,
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
    uint64_t samples[ITERATIONS];

    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_SIG_keypair(s, pk, sk) != OQS_SUCCESS) return 3;
    }
    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &a);
        if (OQS_SIG_keypair(s, pk, sk) != OQS_SUCCESS) return 3;
        clock_gettime(CLOCK_MONOTONIC, &b);
        samples[i] = (uint64_t)elapsed_ns(a, b);
        if (samples[i] == 0) samples[i] = 1;
    }
    emit("ml-dsa", param, "keygen", samples, ITERATIONS,
         s->length_public_key, s->length_secret_key, 0, s->length_signature, 0, 1);

    if (OQS_SIG_keypair(s, pk, sk) != OQS_SUCCESS) return 4;
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_SIG_sign(s, buf, &sl, msg, sizeof(msg) - 1, sk) != OQS_SUCCESS) return 5;
    }
    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &a);
        if (OQS_SIG_sign(s, buf, &sl, msg, sizeof(msg) - 1, sk) != OQS_SUCCESS) return 5;
        clock_gettime(CLOCK_MONOTONIC, &b);
        samples[i] = (uint64_t)elapsed_ns(a, b);
        if (samples[i] == 0) samples[i] = 1;
    }
    emit("ml-dsa", param, "sign", samples, ITERATIONS,
         s->length_public_key, s->length_secret_key, 0, sl, 0, 1);

    if (OQS_SIG_sign(s, buf, &sl, msg, sizeof(msg) - 1, sk) != OQS_SUCCESS) return 6;
    for (int i = 0; i < WARMUPS; i++) {
        if (OQS_SIG_verify(s, msg, sizeof(msg) - 1, buf, sl, pk) != OQS_SUCCESS) return 7;
    }
    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &a);
        if (OQS_SIG_verify(s, msg, sizeof(msg) - 1, buf, sl, pk) != OQS_SUCCESS) return 7;
        clock_gettime(CLOCK_MONOTONIC, &b);
        samples[i] = (uint64_t)elapsed_ns(a, b);
        if (samples[i] == 0) samples[i] = 1;
    }
    emit("ml-dsa", param, "verify", samples, ITERATIONS,
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

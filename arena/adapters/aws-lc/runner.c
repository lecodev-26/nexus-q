#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <openssl/base.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <sys/utsname.h>

#define DEFAULT_ITERATIONS 20
#define DEFAULT_WARMUPS 3
#define MESSAGE "nexusq-pqc-arena-v1"

typedef int (*operation_fn)(void *);

static double elapsed_ns(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1e9 + (double)(b.tv_nsec - a.tv_nsec);
}

static int configured_count(const char *name, int fallback, int minimum) {
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno || end == value || *end != '\0' || parsed < minimum || parsed > 1000000L) {
        fprintf(stderr, "%s must be an integer in [%d, 1000000]; got '%s'\n", name, minimum, value);
        exit(64);
    }
    return (int)parsed;
}

static int iterations(void) { return configured_count("AWSLC_ITERATIONS", DEFAULT_ITERATIONS, 1); }
static int warmups(void) { return configured_count("AWSLC_WARMUPS", DEFAULT_WARMUPS, 0); }
static const char *env_or(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return value && *value ? value : fallback;
}

static void format_cpu_features(char *output, size_t output_len) {
    if (output_len < 3) return;
    snprintf(output, output_len, "[]");
    const char *value = env_or("ARENA_CPU_FEATURES", "");
    if (!*value) return;

    char *copy = strdup(value);
    if (!copy) return;
    size_t used = 0;
    int written = snprintf(output, output_len, "[");
    if (written < 0 || (size_t)written >= output_len) {
        free(copy);
        snprintf(output, output_len, "[]");
        return;
    }
    used = (size_t)written;
    int first = 1;
    char *saveptr = NULL;
    for (char *token = strtok_r(copy, ",", &saveptr); token != NULL;
         token = strtok_r(NULL, ",", &saveptr)) {
        /* CPU feature names are identifiers; reject anything that is not one. */
        if (strspn(token, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != strlen(token)) {
            continue;
        }
        written = snprintf(output + used, output_len - used, "%s\"%s\"", first ? "" : ",", token);
        if (written < 0 || (size_t)written >= output_len - used) {
            free(copy);
            snprintf(output, output_len, "[]");
            return;
        }
        used += (size_t)written;
        first = 0;
    }
    written = snprintf(output + used, output_len - used, "]");
    if (written < 0 || (size_t)written >= output_len - used) {
        snprintf(output, output_len, "[]");
    }
    free(copy);
}

static void meta(char *target, size_t target_len, char *os, size_t os_len,
                 char *cpu, size_t cpu_len) {
    struct utsname u;
    if (getenv("ARENA_TARGET") && getenv("ARENA_OS") && getenv("ARENA_CPU")) {
        snprintf(target, target_len, "%s", getenv("ARENA_TARGET"));
        snprintf(os, os_len, "%s", getenv("ARENA_OS"));
        snprintf(cpu, cpu_len, "%s", getenv("ARENA_CPU"));
        return;
    }
    if (uname(&u) == 0) {
        snprintf(target, target_len, "%s-%s", u.machine, u.sysname);
        snprintf(os, os_len, "%s", u.sysname);
        snprintf(cpu, cpu_len, "%s", u.machine);
        return;
    }
    snprintf(target, target_len, "unknown");
    snprintf(os, os_len, "unknown");
    snprintf(cpu, cpu_len, "unknown");
}

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

typedef struct {
    uint64_t min_ns;
    uint64_t median_ns;
    uint64_t p95_ns;
    double stddev_ns;
} sample_statistics;

static sample_statistics summarize(const uint64_t *samples, size_t count) {
    uint64_t *sorted = malloc(count * sizeof(*sorted));
    if (!sorted) {
        fprintf(stderr, "unable to allocate sample statistics buffer\n");
        exit(70);
    }
    memcpy(sorted, samples, count * sizeof(*sorted));
    qsort(sorted, count, sizeof(*sorted), compare_u64);

    sample_statistics result;
    result.min_ns = sorted[0];
    if (count % 2 == 0) {
        result.median_ns = sorted[count / 2 - 1] / 2 + sorted[count / 2] / 2
                         + ((sorted[count / 2 - 1] % 2 + sorted[count / 2] % 2) / 2);
    } else {
        result.median_ns = sorted[count / 2];
    }
    size_t p95_index = (count * 95 + 99) / 100 - 1;
    result.p95_ns = sorted[p95_index];

    long double mean = 0.0L;
    long double sum_squares = 0.0L;
    for (size_t i = 0; i < count; ++i) {
        long double delta = (long double)samples[i] - mean;
        mean += delta / (long double)(i + 1);
        sum_squares += delta * ((long double)samples[i] - mean);
    }
    result.stddev_ns = sqrt((double)(sum_squares / (long double)count));
    free(sorted);
    return result;
}

static int run_samples(operation_fn operation, void *context, uint64_t *samples,
                       int sample_count, int warmup_count) {
    for (int i = 0; i < warmup_count; ++i) {
        if (!operation(context)) {
            fprintf(stderr, "AWS-LC warmup operation failed at sample %d\n", i);
            return 0;
        }
    }
    for (int i = 0; i < sample_count; ++i) {
        struct timespec start, end;
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 0;
        if (!operation(context)) {
            fprintf(stderr, "AWS-LC measured operation failed at sample %d\n", i);
            return 0;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) return 0;
        double elapsed = elapsed_ns(start, end);
        samples[i] = elapsed < 1.0 ? 1 : (uint64_t)(elapsed + 0.5);
    }
    return 1;
}

static void emit(const char *algorithm, const char *parameter, const char *operation,
                 const uint64_t *samples, int count, int warmup_count,
                 size_t public_key_bytes, size_t secret_key_bytes,
                 size_t ciphertext_bytes, size_t signature_bytes,
                 int has_ciphertext, int has_signature) {
    char target[256], os[128], cpu[256];
    char ciphertext_json[32], signature_json[32], features_json[8192];
    struct timespec now;
    meta(target, sizeof(target), os, sizeof(os), cpu, sizeof(cpu));
    format_cpu_features(features_json, sizeof(features_json));
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        fprintf(stderr, "clock_gettime(CLOCK_REALTIME) failed\n");
        exit(70);
    }
    unsigned long long timestamp = (unsigned long long)now.tv_sec * 1000000000ULL
                                 + (unsigned long long)now.tv_nsec;
    snprintf(ciphertext_json, sizeof(ciphertext_json), has_ciphertext ? "%zu" : "null", ciphertext_bytes);
    snprintf(signature_json, sizeof(signature_json), has_signature ? "%zu" : "null", signature_bytes);
    sample_statistics stats = summarize(samples, (size_t)count);

    printf("{\"schema_version\":1,\"run_id\":\"aws-lc-%s-%s-%s\","
           "\"implementation\":{\"id\":\"aws-lc\",\"version\":\"%s\",\"commit\":\"ec05f25ef5bcb1bf03d2e2f44ba57973a878e0ba\"},"
           "\"algorithm\":{\"id\":\"%s\",\"parameter_set\":\"%s\"},\"operation\":\"%s\","
           "\"environment\":{\"target\":\"%s\",\"os\":\"%s\",\"cpu\":\"%s\","
           "\"cpu_features\":%s,\"compiler\":\"cc\",\"compiler_version\":\"%s\","
           "\"optimization\":\"%s\",\"run_order\":\"%s\",\"harness_version\":\"arena-v2-distribution\"},"
           "\"measurement\":{\"iterations\":%d,\"warmups\":%d,"
           "\"measurement_timestamp_unix_ns\":%llu,\"latency_ns\":%llu,"
           "\"throughput_ops_s\":%.6f,\"memory_bytes\":null,"
           "\"measurement_method\":\"per-operation clock_gettime(CLOCK_MONOTONIC); AWS-LC public EVP API with per-operation context creation; median of raw samples\","
           "\"samples_ns\":[",
           algorithm, parameter, operation, env_or("AWSLC_VERSION", "runtime"),
           algorithm, parameter, operation, target, os, cpu, features_json, __VERSION__,
           env_or("ARENA_OPT", "release"), env_or("ARENA_RUN_ORDER", "unknown"),
           count, warmup_count, timestamp,
           (unsigned long long)stats.median_ns,
           1e9 / (double)stats.median_ns);

    for (int i = 0; i < count; ++i) {
        printf("%s%llu", i ? "," : "", (unsigned long long)samples[i]);
    }
    printf("],\"statistics\":{\"sample_count\":%d,\"min_ns\":%llu,\"median_ns\":%llu,"
           "\"p95_ns\":%llu,\"stddev_ns\":%.3f}},"
           "\"sizes\":{\"public_key_bytes\":%zu,\"secret_key_bytes\":%zu,"
           "\"ciphertext_bytes\":%s,\"signature_bytes\":%s}}\n",
           count, (unsigned long long)stats.min_ns, (unsigned long long)stats.median_ns,
           (unsigned long long)stats.p95_ns, stats.stddev_ns,
           public_key_bytes, secret_key_bytes, ciphertext_json, signature_json);
}

static int generate_kem_key(EVP_PKEY **key, int parameter_nid) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL);
    int ok = ctx && EVP_PKEY_keygen_init(ctx)
          && EVP_PKEY_CTX_kem_set_params(ctx, parameter_nid)
          && EVP_PKEY_keygen(ctx, key);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int generate_dsa_key(EVP_PKEY **key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, NULL);
    int ok = ctx && EVP_PKEY_keygen_init(ctx)
          && EVP_PKEY_CTX_pqdsa_set_params(ctx, NID_MLDSA65)
          && EVP_PKEY_keygen(ctx, key);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

typedef struct {
    int parameter_nid;
} kem_keygen_context;

static int kem_keygen_once(void *opaque) {
    const kem_keygen_context *ctx = opaque;
    EVP_PKEY *key = NULL;
    int ok = generate_kem_key(&key, ctx->parameter_nid);
    EVP_PKEY_free(key);
    return ok;
}

typedef struct {
    EVP_PKEY *key;
    unsigned char *ciphertext;
    size_t ciphertext_capacity;
    size_t ciphertext_len;
    unsigned char *secret;
    size_t secret_capacity;
    size_t secret_len;
    unsigned char *decapsulated_secret;
    size_t decapsulated_secret_len;
} kem_context;

static int kem_encaps_once(void *opaque) {
    kem_context *ctx = opaque;
    EVP_PKEY_CTX *op = EVP_PKEY_CTX_new(ctx->key, NULL);
    size_t ciphertext_len = ctx->ciphertext_capacity;
    size_t secret_len = ctx->secret_capacity;
    int ok = op && EVP_PKEY_encapsulate(op, ctx->ciphertext, &ciphertext_len,
                                        ctx->secret, &secret_len);
    EVP_PKEY_CTX_free(op);
    if (ok) {
        ctx->ciphertext_len = ciphertext_len;
        ctx->secret_len = secret_len;
    }
    return ok;
}

static int kem_decaps_once(void *opaque) {
    kem_context *ctx = opaque;
    EVP_PKEY_CTX *op = EVP_PKEY_CTX_new(ctx->key, NULL);
    size_t secret_len = ctx->secret_capacity;
    int ok = op && EVP_PKEY_decapsulate(op, ctx->decapsulated_secret, &secret_len,
                                        ctx->ciphertext, ctx->ciphertext_len);
    EVP_PKEY_CTX_free(op);
    if (ok) ctx->decapsulated_secret_len = secret_len;
    return ok;
}

static int dsa_keygen_once(void *unused) {
    (void)unused;
    EVP_PKEY *key = NULL;
    int ok = generate_dsa_key(&key);
    EVP_PKEY_free(key);
    return ok;
}

typedef struct {
    EVP_PKEY *key;
    const unsigned char *message;
    size_t message_len;
    unsigned char *signature;
    size_t signature_capacity;
    size_t signature_len;
} dsa_context;

static int dsa_sign_once(void *opaque) {
    dsa_context *ctx = opaque;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    size_t signature_len = ctx->signature_capacity;
    int ok = md && EVP_DigestSignInit(md, NULL, NULL, NULL, ctx->key)
          && EVP_DigestSign(md, ctx->signature, &signature_len,
                            ctx->message, ctx->message_len);
    EVP_MD_CTX_free(md);
    if (ok) ctx->signature_len = signature_len;
    return ok;
}

static int dsa_verify_once(void *opaque) {
    dsa_context *ctx = opaque;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ok = md && EVP_DigestVerifyInit(md, NULL, NULL, NULL, ctx->key)
          && EVP_DigestVerify(md, ctx->signature, ctx->signature_len,
                              ctx->message, ctx->message_len) == 1;
    EVP_MD_CTX_free(md);
    return ok;
}

static int kem_parameter(const char *parameter, int parameter_nid,
                         size_t public_key_bytes, size_t secret_key_bytes,
                         size_t expected_ciphertext_bytes) {
    int count = iterations(), warmup_count = warmups();
    uint64_t *samples = calloc((size_t)count, sizeof(*samples));
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *size_ctx = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *secret = NULL;
    unsigned char *decapsulated_secret = NULL;
    kem_keygen_context keygen = {parameter_nid};
    kem_context context = {0};
    size_t ciphertext_len = 0, secret_len = 0;
    int result = 1;
    if (!samples) return 1;

    if (!run_samples(kem_keygen_once, &keygen, samples, count, warmup_count)) goto cleanup;
    emit("ml-kem", parameter, "keygen", samples, count, warmup_count,
         public_key_bytes, secret_key_bytes, expected_ciphertext_bytes, 0, 1, 0);

    if (!generate_kem_key(&key, parameter_nid)) goto cleanup;
    size_ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!size_ctx || !EVP_PKEY_encapsulate(size_ctx, NULL, &ciphertext_len, NULL, &secret_len)) {
        goto cleanup;
    }
    if (ciphertext_len != expected_ciphertext_bytes || secret_len == 0) {
        fprintf(stderr, "AWS-LC ML-KEM-%s unexpected output sizes: ciphertext=%zu secret=%zu\n",
                parameter, ciphertext_len, secret_len);
        goto cleanup;
    }
    EVP_PKEY_CTX_free(size_ctx);
    size_ctx = NULL;

    ciphertext = OPENSSL_malloc(ciphertext_len);
    secret = OPENSSL_malloc(secret_len);
    decapsulated_secret = OPENSSL_malloc(secret_len);
    if (!ciphertext || !secret || !decapsulated_secret) goto cleanup;

    context.key = key;
    context.ciphertext = ciphertext;
    context.ciphertext_capacity = ciphertext_len;
    context.secret = secret;
    context.secret_capacity = secret_len;
    context.decapsulated_secret = decapsulated_secret;

    /* Fail closed if this parameter set cannot complete a correct KEM round trip. */
    if (!kem_encaps_once(&context) || context.ciphertext_len != ciphertext_len ||
        context.secret_len != secret_len || !kem_decaps_once(&context) ||
        context.decapsulated_secret_len != secret_len ||
        memcmp(context.secret, context.decapsulated_secret, secret_len) != 0) {
        fprintf(stderr, "AWS-LC ML-KEM-%s encapsulation/decapsulation self-check failed\n", parameter);
        goto cleanup;
    }

    if (!run_samples(kem_encaps_once, &context, samples, count, warmup_count)) goto cleanup;
    emit("ml-kem", parameter, "encaps", samples, count, warmup_count,
         public_key_bytes, secret_key_bytes, ciphertext_len, 0, 1, 0);
    if (!run_samples(kem_decaps_once, &context, samples, count, warmup_count)) goto cleanup;
    emit("ml-kem", parameter, "decaps", samples, count, warmup_count,
         public_key_bytes, secret_key_bytes, ciphertext_len, 0, 1, 0);

    result = 0;
cleanup:
    EVP_PKEY_CTX_free(size_ctx);
    OPENSSL_free(ciphertext);
    OPENSSL_free(secret);
    OPENSSL_free(decapsulated_secret);
    EVP_PKEY_free(key);
    free(samples);
    if (result != 0) fprintf(stderr, "AWS-LC ML-KEM-%s benchmark failed\n", parameter);
    return result;
}

static int kem(void) {
    if (kem_parameter("768", NID_MLKEM768, 1184, 2400, 1088) != 0) return 1;
    if (kem_parameter("1024", NID_MLKEM1024, 1568, 3168, 1568) != 0) return 1;
    return 0;
}

static int dsa(void) {
    int count = iterations(), warmup_count = warmups();
    uint64_t *samples = calloc((size_t)count, sizeof(*samples));
    EVP_PKEY *key = NULL;
    const unsigned char message[] = MESSAGE;
    const size_t signature_capacity = 4096;
    unsigned char *signature = OPENSSL_malloc(signature_capacity);
    if (!samples || !signature) { free(samples); OPENSSL_free(signature); return 1; }

    if (!run_samples(dsa_keygen_once, NULL, samples, count, warmup_count)) goto fail;
    emit("ml-dsa", "65", "keygen", samples, count, warmup_count,
         1952, 4032, 0, 3309, 0, 1);

    if (!generate_dsa_key(&key)) goto fail;
    dsa_context context = {key, message, sizeof(message) - 1,
                           signature, signature_capacity, 0};
    if (!dsa_sign_once(&context)) goto fail;
    if (!run_samples(dsa_sign_once, &context, samples, count, warmup_count)) goto fail;
    emit("ml-dsa", "65", "sign", samples, count, warmup_count,
         1952, 4032, 0, context.signature_len, 0, 1);
    if (!run_samples(dsa_verify_once, &context, samples, count, warmup_count)) goto fail;
    emit("ml-dsa", "65", "verify", samples, count, warmup_count,
         1952, 4032, 0, context.signature_len, 0, 1);

    EVP_PKEY_free(key);
    OPENSSL_free(signature);
    free(samples);
    return 0;

fail:
    EVP_PKEY_free(key);
    OPENSSL_free(signature);
    free(samples);
    fprintf(stderr, "AWS-LC ML-DSA benchmark failed\n");
    return 1;
}

int main(void) {
    if (kem() != 0) return 1;
    if (dsa() != 0) return 2;
    return 0;
}

/* Benchmark-only RNG bridge. Keep production/default builds on getrandom via Rust. */
#include <stddef.h>
#include <stdint.h>

/* aws-lc-sys 0.46.0 pins this exported symbol name through its symbol prefix. */
extern int aws_lc_0_46_0_RAND_bytes(uint8_t *buf, size_t len);

int nq_randombytes(uint8_t *out, size_t len) {
    if (len == 0) return 0;
    if (out == NULL) return -1;
    return aws_lc_0_46_0_RAND_bytes(out, len) == 1 ? 0 : -1;
}

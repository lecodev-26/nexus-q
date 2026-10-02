// Smoke test for the C SDK.
//
// Build:
//   cc -I crates/nexusq-c/include smoke.c \
//      -L target/debug -lnexusq -o smoke
//
// Run:
//   LD_LIBRARY_PATH=target/debug ./smoke
//
// The smoke test creates a vault, checks its format version and
// removes it again. It needs a writable directory; the HOME
// environment variable is used.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nexusq.h"

int main(void) {
    printf("nexusq version: %s\n", nexusq_version());

    const char *home = getenv("HOME");
    if (home == NULL) {
        fprintf(stderr, "HOME is not set\n");
        return 1;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/nexusq_c_smoke.nqv", home);

    const char *password = "smoke-test";
    const char *label = "c-smoke";

    remove(path);

    int rc = nexusq_vault_create(path, password, label);
    if (rc != 0) {
        fprintf(stderr, "vault create failed: %s\n", nexusq_last_error_message());
        return 1;
    }
    printf("vault created at %s\n", path);

    int version = nexusq_vault_format_version(path);
    if (version < 0) {
        fprintf(stderr, "format check failed: %s\n", nexusq_last_error_message());
        remove(path);
        return 1;
    }
    printf("vault format version: %d\n", version);

    remove(path);
    printf("cleaned up\n");
    return 0;
}

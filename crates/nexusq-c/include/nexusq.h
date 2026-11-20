#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Returns the library version as a static, borrowed NUL-terminated C string.
 *
 * The pointer is owned by the library and must not be passed to
 * `nexusq_string_free`.
 */
const char *nexusq_version(void);

/**
 * Returns the compiled cryptographic provider (`rustcrypto` or `native-experimental`).
 * The returned pointer is static/borrowed and must not be freed.
 */
const char *nexusq_backend_name(void);

/** Returns 1 if the compiled cryptographic provider is experimental, otherwise 0. */
uint8_t nexusq_backend_is_experimental(void);

/**
 * Frees a heap-allocated C string explicitly documented as owned by NEXUS-Q.
 *
 * Passing null is a no-op. Borrowed/static pointers returned by
 * `nexusq_version`, `nexusq_backend_name`, or `nexusq_last_error_message`
 * must not be passed to this function. No current C ABI function returns an
 * owned heap-allocated string; this function is reserved for future owned
 * string-returning APIs.
 *
 * The pointer must be the exact allocation returned by a NEXUS-Q function
 * whose documentation explicitly states that it is compatible with this
 * deallocator. Passing borrowed, static, interior, already-freed, or foreign
 * pointers is undefined behavior.
 */
void nexusq_string_free(char *s);

/**
 * Returns the last error message on the calling thread, or null.
 *
 * The returned pointer is borrowed, owned by the library, and remains valid
 * only until the next NEXUS-Q call on the same thread. Do not free it.
 */
const char *nexusq_last_error_message(void);

/**
 * Creates a new vault at `path` with the given `password`.
 *
 * Both strings must be NUL-terminated and valid UTF-8. `label` may
 * be null to create a vault without a label.
 *
 * Returns 0 on success and a negative code on failure. On failure,
 * call `nexusq_last_error_message` to retrieve the reason.
 *
 * # Safety
 *
 * `path` and `password` must be valid NUL-terminated C strings.
 * `label` must be null or a valid NUL-terminated C string.
 */
int32_t nexusq_vault_create(const char *path, const char *password, const char *label);

/**
 * Returns the version byte of the vault at `path`, or a negative
 * code on failure.
 *
 * # Safety
 *
 * `path` must be a valid NUL-terminated C string.
 */
int32_t nexusq_vault_format_version(const char *path);

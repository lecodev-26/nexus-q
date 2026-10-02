#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Returns the library version as a static NUL-terminated string.
 *
 * The returned pointer is owned by the library and must not be
 * freed by the caller.
 */
const char *nexusq_version(void);

/**
 * Frees a string previously returned by a NEXUS-Q function.
 *
 * Passing a null pointer is a no-op. Passing a pointer not returned
 * by this library is undefined behavior.
 *
 * # Safety
 *
 * `s` must be a pointer previously returned by one of the functions
 * in this crate, or null.
 */
void nexusq_string_free(char *s);

/**
 * Returns the last error message on the calling thread, or null.
 *
 * The returned pointer is owned by the library and remains valid
 * until the next NEXUS-Q call on the same thread.
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

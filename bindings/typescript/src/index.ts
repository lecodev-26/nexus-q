/**
 * NEXUS-Q TypeScript bindings.
 *
 * This is a thin FFI wrapper over the stable C SDK. It does not reimplement
 * cryptography or business logic; every operation delegates to libnexusq.
 *
 * The library is resolved from `NEXUSQ_LIBRARY` when set, otherwise the
 * system loader default (`nexusq`) is used. Build the C SDK first:
 *
 *   cargo build -p nexusq-c
 *   NEXUSQ_LIBRARY=target/debug/libnexusq.so node dist/smoke.js
 */
import koffi from "koffi";

const libraryPath = process.env.NEXUSQ_LIBRARY || "nexusq";
const lib = koffi.load(libraryPath);

// Raw C ABI surface of the NEXUS-Q C SDK.
const nexusq_version = lib.func("const char *nexusq_version()");
const nexusq_backend_name = lib.func("const char *nexusq_backend_name()");
const nexusq_backend_is_experimental = lib.func("uint8_t nexusq_backend_is_experimental()");
const nexusq_last_error_message = lib.func(
  "const char *nexusq_last_error_message()"
);
const nexusq_vault_create = lib.func(
  "int32_t nexusq_vault_create(const char *path, const char *password, const char *label)"
);
const nexusq_vault_format_version = lib.func(
  "int32_t nexusq_vault_format_version(const char *path)"
);

/** Error raised when a NEXUS-Q operation fails. */
export class NexusqError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NexusqError";
  }
}

/** Returns the library version string. */
export function version(): string {
  return nexusq_version() as string;
}

/** Reports the provider compiled into the loaded library; it does not switch providers. */
export function backendInfo(): { name: string; experimental: boolean; nativeAvailable: boolean } {
  const name = nexusq_backend_name() as string;
  const experimental = (nexusq_backend_is_experimental() as number) !== 0;
  return { name, experimental, nativeAvailable: name === "native-experimental" };
}

/** Returns the last error message on the calling thread, or null. */
export function lastError(): string | null {
  return (nexusq_last_error_message() as string | null) ?? null;
}

/** A NEXUS-Q vault created on disk. */
export class Vault {
  /** Path of the vault file on disk. */
  readonly path: string;
  /** Format version byte of the vault (currently 1). */
  readonly formatVersion: number;

  private constructor(path: string, formatVersion: number) {
    this.path = path;
    this.formatVersion = formatVersion;
  }

  /**
   * Creates a new vault at `path` with the given `password`.
   * `label` is optional and may be null.
   *
   * Throws {@link NexusqError} when the operation fails; the message is
   * borrowed from the library's last error.
   */
  static create(path: string, password: string, label?: string | null): Vault {
    const rc = nexusq_vault_create(path, password, label ?? null) as number;
    if (rc !== 0) {
      throw new NexusqError(lastError() ?? "NEXUS-Q operation failed");
    }
    const formatVersion = nexusq_vault_format_version(path) as number;
    if (formatVersion < 0) {
      throw new NexusqError(lastError() ?? "NEXUS-Q operation failed");
    }
    return new Vault(path, formatVersion);
  }
}

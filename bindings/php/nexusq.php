<?php

declare(strict_types=1);

/**
 * NEXUS-Q PHP bindings.
 *
 * This is a thin FFI wrapper over the stable C SDK. It does not reimplement
 * cryptography or business logic; operations delegate to libnexusq.
 */
final class Nexusq
{
    private static ?FFI $ffi = null;

    private static function ffi(): FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }

        $library = getenv('NEXUSQ_LIBRARY') ?: 'libnexusq.so';
        $header = <<<CDEF
            const char *nexusq_version(void);
            const char *nexusq_last_error_message(void);
            int32_t nexusq_vault_create(const char *path, const char *password, const char *label);
            int32_t nexusq_vault_format_version(const char *path);
        CDEF;

        self::$ffi = FFI::cdef($header, $library);
        return self::$ffi;
    }

    public static function version(): string
    {
        return self::ffi()->nexusq_version();
    }

    public static function lastError(): ?string
    {
        $ptr = self::ffi()->nexusq_last_error_message();
        return $ptr === null ? null : $ptr;
    }

    public static function vaultCreate(string $path, string $password, ?string $label = null): Vault
    {
        $rc = self::ffi()->nexusq_vault_create($path, $password, $label);
        if ($rc !== 0) {
            throw new NexusqException(self::lastError() ?? 'NEXUS-Q operation failed');
        }

        $version = self::ffi()->nexusq_vault_format_version($path);
        if ($version < 0) {
            throw new NexusqException(self::lastError() ?? 'NEXUS-Q operation failed');
        }

        return new Vault($path, $version);
    }
}

final class Vault
{
    public function __construct(
        public readonly string $path,
        public readonly int $formatVersion,
    ) {
    }
}

final class NexusqException extends RuntimeException
{
}

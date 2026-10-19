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
    private const RUNTIME_VERSION = '4.1.0';
    private static ?FFI $ffi = null;

    private static function resolveLibrary(): string
    {
        $override = getenv('NEXUSQ_LIBRARY');
        if ($override !== false && $override !== '') {
            return $override;
        }

        $os = strtolower(PHP_OS_FAMILY);
        $arch = strtolower(php_uname('m'));
        if ($os === 'linux' && (is_file('/lib/ld-musl-x86_64.so.1') || is_file('/lib/ld-musl-aarch64.so.1') || is_file('/lib/ld-musl-armhf.so.1'))) {
            throw new RuntimeException('Prebuilt NEXUS-Q Linux runtimes require glibc, not musl/Alpine; set NEXUSQ_LIBRARY to a compatible build.');
        }
        if ($os === 'linux' && in_array($arch, ['x86_64', 'amd64'], true)) {
            [$asset, $localName] = ['nexusq-sdk-runtime-linux-x64.so', 'libnexusq.so'];
        } elseif ($os === 'linux' && in_array($arch, ['aarch64', 'arm64'], true)) {
            [$asset, $localName] = ['nexusq-sdk-runtime-linux-arm64.so', 'libnexusq.so'];
        } elseif ($os === 'darwin' && in_array($arch, ['arm64', 'aarch64'], true)) {
            [$asset, $localName] = ['nexusq-sdk-runtime-macos-arm64.dylib', 'libnexusq.dylib'];
        } elseif ($os === 'windows' && in_array($arch, ['x86_64', 'amd64'], true)) {
            [$asset, $localName] = ['nexusq-sdk-runtime-windows-x64.dll', 'nexusq.dll'];
        } else {
            throw new RuntimeException("No prebuilt NEXUS-Q runtime for {$os}/{$arch}; set NEXUSQ_LIBRARY to a compatible library path.");
        }

        $cache = rtrim(getenv('HOME') ?: sys_get_temp_dir(), DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR . '.cache' . DIRECTORY_SEPARATOR . 'nexusq' . DIRECTORY_SEPARATOR . self::RUNTIME_VERSION . DIRECTORY_SEPARATOR . $asset;
        if (!is_dir($cache) && !mkdir($cache, 0700, true) && !is_dir($cache)) {
            throw new RuntimeException("Cannot create NEXUS-Q runtime cache at {$cache}");
        }
        $library = $cache . DIRECTORY_SEPARATOR . $localName;
        $digestFile = $library . '.sha256';
        if (is_file($library) && is_file($digestFile)
            && hash_file('sha256', $library) === trim((string) file_get_contents($digestFile))) {
            return $library;
        }

        $base = 'https://github.com/lecodev-26/nexus-q/releases/download/v' . self::RUNTIME_VERSION . '/';
        $context = stream_context_create(['http' => ['follow_location' => 1, 'user_agent' => 'NEXUS-Q PHP SDK', 'timeout' => 60]]);
        $checksums = @file_get_contents($base . 'NATIVE-RUNTIME-SHA256SUMS', false, $context);
        if ($checksums === false) {
            throw new RuntimeException('Unable to download NEXUS-Q runtime checksums; check network access or set NEXUSQ_LIBRARY.');
        }
        $expected = null;
        foreach (preg_split('/\r?\n/', $checksums) as $line) {
            if (str_ends_with(trim($line), '  ' . $asset)) {
                $expected = preg_split('/\s+/', trim($line))[0];
                break;
            }
        }
        if ($expected === null) {
            throw new RuntimeException("No published checksum for {$asset}");
        }
        $bytes = @file_get_contents($base . $asset, false, $context);
        if ($bytes === false) {
            throw new RuntimeException("Unable to download native runtime {$asset}");
        }
        $actual = hash('sha256', $bytes);
        if (!hash_equals(strtolower($expected), $actual)) {
            throw new RuntimeException("SHA-256 mismatch for {$asset}; refusing to load an unverified runtime");
        }
        $temporary = $library . '.download';
        if (file_put_contents($temporary, $bytes, LOCK_EX) === false || !rename($temporary, $library)) {
            @unlink($temporary);
            throw new RuntimeException("Unable to cache native runtime at {$library}");
        }
        file_put_contents($digestFile, $actual . "\n", LOCK_EX);
        return $library;
    }

    private static function ffi(): FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }

        $library = self::resolveLibrary();
        $header = <<<CDEF
            const char *nexusq_version(void);
            const char *nexusq_backend_name(void);
            uint8_t nexusq_backend_is_experimental(void);
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

    /** Reports the compile-time crypto provider; this does not change selection. */
    public static function backendInfo(): array
    {
        $ffi = self::ffi();
        $name = $ffi->nexusq_backend_name();
        return [
            'name' => $name,
            'experimental' => $ffi->nexusq_backend_is_experimental() !== 0,
            'native_available' => $name === 'native-experimental',
        ];
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

# NEXUS-Q PHP SDK

PHP bindings for NEXUS-Q using PHP FFI over the stable C SDK ABI.

## Architecture

```text
NEXUS-Q Core
    ↓
C SDK / stable ABI
    ├── C
    ├── C++
    ├── Go
    ├── Ruby FFI
    └── PHP FFI
```

The PHP layer contains no cryptography or independent security policy. It
loads `libnexusq` and delegates operations to the C ABI.

## Requirements

- PHP 8.4 or newer
- PHP FFI extension enabled
- `libnexusq.so` available to the PHP process

## Usage

```php
<?php

require __DIR__ . '/nexusq.php';

printf("NEXUS-Q %s\n", Nexusq::version());

$vault = Nexusq::vaultCreate('/tmp/example.nqv', 'strong-password', 'example');

echo $vault->path, PHP_EOL;
echo $vault->formatVersion, PHP_EOL;
```

Set `NEXUSQ_LIBRARY` when the library is not in the platform default search
path:

```text
NEXUSQ_LIBRARY=/path/to/libnexusq.so
```

## Termux / Debian smoke test

On Termux, the PHP runtime can be provided by the existing Debian proot
environment. Build the C SDK for that environment first:

```bash
proot-distro login debian -- bash -lc 'cd /data/data/com.termux/files/home/projects/nexusq && cargo build -p nexusq-c'
```

Then run PHP with FFI enabled and point it at the resulting library:

```bash
proot-distro login debian -- bash -lc 'NEXUSQ_LIBRARY=/data/data/com.termux/files/home/projects/nexusq/target/debug/libnexusq.so php bindings/php/smoke.php'
```

The smoke test verifies version reporting and vault creation through the C
ABI.

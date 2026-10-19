<?php

declare(strict_types=1);

require __DIR__ . '/nexusq.php';

$path = sys_get_temp_dir() . '/nexusq-php-smoke-' . getmypid() . '.vault';

try {
    $vault = Nexusq::vaultCreate($path, 'correct horse battery staple', 'php-smoke');

    printf("nexusq version: %s\n", Nexusq::version());
    $provider = Nexusq::backendInfo();
    if ($provider['name'] === '' || $provider['native_available'] !== ($provider['name'] === 'native-experimental') || $provider['experimental'] !== $provider['native_available']) {
        throw new RuntimeException('inconsistent backend metadata');
    }
    printf("PQC backend: %s\n", $provider['name']);
    printf("vault created at %s\n", $vault->path);
    printf("vault format version: %d\n", $vault->formatVersion);
    echo "smoke test passed\n";
} finally {
    if (is_file($path)) {
        unlink($path);
    }
}

package io.github.lecodev26.nexusq;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NexusqTest {

    @Test
    void versionIsReported() {
        assertTrue(Nexusq.version().startsWith("4.1.0"));
    }

    @Test
    void vaultCreateRoundTrip(@TempDir Path dir) {
        Path path = dir.resolve("vault.nqv");
        Nexusq.Vault vault = Nexusq.Vault.create(path.toString(), "java-test", "java-smoke");
        assertTrue(Files.exists(path));
        assertEquals(path.toString(), vault.path);
        assertEquals(1, vault.formatVersion);
    }

    @Test
    void vaultCreateWithoutLabel(@TempDir Path dir) {
        Path path = dir.resolve("vault.nqv");
        Nexusq.Vault vault = Nexusq.Vault.create(path.toString(), "java-test", null);
        assertEquals(1, vault.formatVersion);
    }

    @Test
    void failuresCarryLibraryMessages(@TempDir Path dir) {
        Path missing = dir.resolve("no").resolve("parent").resolve("v.nqv");
        NexusqException e = assertThrows(
                NexusqException.class,
                () -> Nexusq.Vault.create(missing.toString(), "x", null));
        assertNotNull(e.getMessage());
        assertTrue(!e.getMessage().isBlank());
    }
}

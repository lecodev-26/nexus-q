package io.github.lecodev26.nexusq.examples;

import io.github.lecodev26.nexusq.Nexusq;

/**
 * Smoke test for the NEXUS-Q Java SDK.
 *
 * <p>Run from the repository root after {@code mvn -f bindings/java package}:
 *
 * <pre>java -cp bindings/java/target/classes:$(mvn -f bindings/java dependency:build-classpath -Dmdep.outputFile=/dev/stdout -q) io.github.lecodev26.nexusq.examples.Smoke</pre>
 */
public final class Smoke {

    public static void main(String[] args) throws Exception {
        System.out.println("nexusq version: " + Nexusq.version());

        java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("nexusq_java_smoke_");
        java.nio.file.Path path = dir.resolve("vault.nqv");

        Nexusq.Vault vault = Nexusq.Vault.create(path.toString(), "java-test", "java-smoke");
        if (!java.nio.file.Files.exists(path)) {
            throw new AssertionError("vault file was not created");
        }
        if (!vault.path.equals(path.toString())) {
            throw new AssertionError("vault.path does not match input");
        }
        if (vault.formatVersion != 1) {
            throw new AssertionError("format_version must be 1, got " + vault.formatVersion);
        }
        System.out.println("vault created at " + vault.path);
        System.out.println("vault format version: " + vault.formatVersion);

        boolean raised = false;
        try {
            Nexusq.Vault.create(dir.resolve("no").resolve("parent").resolve("v.nqv").toString(), "x", null);
        } catch (io.github.lecodev26.nexusq.NexusqException e) {
            raised = e.getMessage() != null && !e.getMessage().isBlank();
        }
        if (!raised) {
            throw new AssertionError("creating a vault under a missing directory must fail with a message");
        }
        System.out.println("error propagation: ok");
        System.out.println("smoke test passed");
    }
}

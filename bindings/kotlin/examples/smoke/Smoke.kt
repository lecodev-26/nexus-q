package io.github.lecodev26.nexusq.kotlin.examples

import io.github.lecodev26.nexusq.kotlin.Nexusq
import java.nio.file.Files

/**
 * Smoke test for the NEXUS-Q Kotlin SDK.
 *
 * Run from the repository root after compiling with kotlinc (see README):
 *
 *   NEXUSQ_LIBRARY=target/debug/libnexusq.so java -cp ... examples.Smoke
 */
fun main() {
    println("nexusq version: ${Nexusq.version()}")

    val dir = Files.createTempDirectory("nexusq_kotlin_smoke_")
    val path = dir.resolve("vault.nqv")

    val vault = Nexusq.Vault.create(path.toString(), "kotlin-test", "kotlin-smoke")
    check(Files.exists(path)) { "vault file was not created" }
    check(vault.path == path.toString()) { "vault.path does not match input" }
    check(vault.formatVersion == 1) { "format_version must be 1, got ${vault.formatVersion}" }
    println("vault created at ${vault.path}")
    println("vault format version: ${vault.formatVersion}")

    var raised = false
    try {
        Nexusq.Vault.create(dir.resolve("no").resolve("parent").resolve("v.nqv").toString(), "x")
    } catch (e: IllegalStateException) {
        raised = !e.message.isNullOrBlank()
    }
    check(raised) { "creating a vault under a missing directory must fail with a message" }
    println("error propagation: ok")
    println("smoke test passed")
}

@file:Suppress("unused")

package io.github.lecodev26.nexusq.kotlin

import com.sun.jna.Library
import com.sun.jna.Native

/**
 * NEXUS-Q Kotlin bindings.
 *
 * This is a thin JNA wrapper over the stable C SDK. It does not reimplement
 * cryptography or business logic; every operation delegates to libnexusq.
 *
 * The library is resolved from the `NEXUSQ_LIBRARY` environment variable when
 * set, otherwise the system loader default (`nexusq`) is used. Build the C SDK
 * first: `cargo build -p nexusq-c`.
 */
object Nexusq {

    init {
        // Force UTF-8 for JNA string marshalling regardless of the host JVM
        // default charset, matching the C SDK contract.
        System.setProperty("jna.encoding", "UTF-8")
    }

    private interface CApi : Library {
        fun nexusq_version(): String
        fun nexusq_last_error_message(): String?
        fun nexusq_vault_create(path: String, password: String, label: String?): Int
        fun nexusq_vault_format_version(path: String): Int
    }

    private val C: CApi = Native.load(
        System.getenv("NEXUSQ_LIBRARY") ?: "nexusq",
        CApi::class.java
    )

    /** Returns the library version string. */
    fun version(): String = C.nexusq_version()

    /** Returns the last error message on the calling thread, or null. */
    fun lastError(): String? = C.nexusq_last_error_message()

    /** A NEXUS-Q vault created on disk. */
    data class Vault(val path: String, val formatVersion: Int) {
        companion object {
            /**
             * Creates a new vault at [path] with the given [password].
             * [label] is optional and may be null.
             *
             * @throws IllegalStateException when the operation fails; the
             *     message is borrowed from the library's last error.
             */
            fun create(path: String, password: String, label: String? = null): Vault {
                check(C.nexusq_vault_create(path, password, label) == 0) {
                    lastError() ?: "NEXUS-Q operation failed"
                }
                val formatVersion = C.nexusq_vault_format_version(path)
                check(formatVersion >= 0) { lastError() ?: "NEXUS-Q operation failed" }
                return Vault(path, formatVersion)
            }
        }
    }
}

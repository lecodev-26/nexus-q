@file:Suppress("unused")

package io.github.lecodev26.nexusq.kotlin

import com.sun.jna.Library
import com.sun.jna.Native
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/**
 * NEXUS-Q Kotlin bindings.
 *
 * This is a thin JNA wrapper over the stable C SDK. It does not reimplement
 * cryptography or business logic; every operation delegates to libnexusq.
 *
 * Published releases obtain the version-matched, SHA-256-verified native runtime
 * automatically on supported targets. `NEXUSQ_LIBRARY` overrides that resolver.
 */
object Nexusq {

    init {
        // Force UTF-8 for JNA string marshalling regardless of the host JVM
        // default charset, matching the C SDK contract.
        System.setProperty("jna.encoding", "UTF-8")
    }

    private interface CApi : Library {
        fun nexusq_version(): String
        fun nexusq_backend_name(): String
        fun nexusq_backend_is_experimental(): Byte
        fun nexusq_last_error_message(): String?
        fun nexusq_vault_create(path: String, password: String, label: String?): Int
        fun nexusq_vault_format_version(path: String): Int
    }

    private const val RUNTIME_VERSION = "4.1.2"

    private val C: CApi = Native.load(resolveLibrary(), CApi::class.java)

    private fun resolveLibrary(): String {
        System.getenv("NEXUSQ_LIBRARY")?.takeIf { it.isNotBlank() }?.let { return it }
        val asset = runtimeAsset()
        val cache = Path.of(System.getProperty("user.home"), ".cache", "nexusq", RUNTIME_VERSION, asset.assetName)
        val library = cache.resolve(asset.localName)
        val digestFile = cache.resolve(asset.localName + ".sha256")
        try {
            Files.createDirectories(cache)
            if (Files.isRegularFile(library) && Files.isRegularFile(digestFile)) {
                val expected = Files.readString(digestFile, StandardCharsets.US_ASCII).trim()
                if (expected == sha256(Files.readAllBytes(library))) return library.toAbsolutePath().toString()
            }
            val base = "https://github.com/lecodev-26/nexus-q/releases/download/v$RUNTIME_VERSION/"
            val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS)
                .connectTimeout(java.time.Duration.ofSeconds(10)).build()
            val sums = get(client, base + "NATIVE-RUNTIME-SHA256SUMS")
            val expected = String(sums, StandardCharsets.UTF_8).lineSequence()
                .firstOrNull { it.trim().endsWith("  " + asset.assetName) }
                ?.trim()?.split(Regex("\\s+"))?.first()
                ?: throw IOException("No release checksum found for ${asset.assetName}")
            val binary = get(client, base + asset.assetName)
            val actual = sha256(binary)
            if (!actual.equals(expected, ignoreCase = true)) throw IOException("SHA-256 mismatch for ${asset.assetName}")
            val temporary = cache.resolve(asset.localName + ".download")
            Files.write(temporary, binary)
            try {
                Files.move(temporary, library, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary, library, StandardCopyOption.REPLACE_EXISTING)
            }
            Files.writeString(digestFile, "$actual\n", StandardCharsets.US_ASCII)
            return library.toAbsolutePath().toString()
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            throw IllegalStateException("Unable to obtain a verified NEXUS-Q $RUNTIME_VERSION native runtime. " +
                "Set NEXUSQ_LIBRARY to a compatible library path. ${e.message}", e)
        }
    }

    private fun get(client: HttpClient, url: String): ByteArray {
        val response = client.send(HttpRequest.newBuilder(URI.create(url)).timeout(java.time.Duration.ofSeconds(60)).GET().build(), HttpResponse.BodyHandlers.ofByteArray())
        if (response.statusCode() != 200) throw IOException("HTTP ${response.statusCode()} downloading $url")
        return response.body()
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun runtimeAsset(): RuntimeAsset {
        val os = System.getProperty("os.name", "").lowercase()
        val arch = System.getProperty("os.arch", "").lowercase()
        if (os.contains("linux") && isMuslLinux())
            throw IllegalStateException("Prebuilt NEXUS-Q Linux runtimes require glibc, not musl/Alpine. Set NEXUSQ_LIBRARY to a compatible build.")
        if (os.contains("linux") && arch in setOf("amd64", "x86_64"))
            return RuntimeAsset("nexusq-sdk-runtime-linux-x64.so", "libnexusq.so")
        if (os.contains("linux") && arch in setOf("aarch64", "arm64"))
            return RuntimeAsset("nexusq-sdk-runtime-linux-arm64.so", "libnexusq.so")
        if (os.contains("mac") && arch in setOf("aarch64", "arm64"))
            return RuntimeAsset("nexusq-sdk-runtime-macos-arm64.dylib", "libnexusq.dylib")
        if (os.contains("win") && arch in setOf("amd64", "x86_64"))
            return RuntimeAsset("nexusq-sdk-runtime-windows-x64.dll", "nexusq.dll")
        throw IllegalStateException("No prebuilt NEXUS-Q runtime for $os/$arch. Set NEXUSQ_LIBRARY to a compatible library path.")
    }

    private fun isMuslLinux(): Boolean = listOf(
        "/lib/ld-musl-x86_64.so.1", "/lib/ld-musl-aarch64.so.1", "/lib/ld-musl-armhf.so.1"
    ).any { Files.exists(Path.of(it)) }

    private data class RuntimeAsset(val assetName: String, val localName: String)

    /** Returns the library version string. */
    fun version(): String = C.nexusq_version()

    data class BackendInfo(val name: String, val experimental: Boolean, val nativeAvailable: Boolean)

    /** Reports the provider compiled into the loaded library; it does not switch providers. */
    fun backendInfo(): BackendInfo {
        val name = C.nexusq_backend_name()
        return BackendInfo(name, C.nexusq_backend_is_experimental().toInt() != 0, name == "native-experimental")
    }

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

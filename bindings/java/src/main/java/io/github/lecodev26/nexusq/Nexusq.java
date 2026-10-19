package io.github.lecodev26.nexusq;

import com.sun.jna.Library;
import com.sun.jna.Native;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * NEXUS-Q Java bindings.
 *
 * <p>This is a thin JNA wrapper over the stable C SDK. It does not reimplement
 * cryptography or business logic; every operation delegates to libnexusq.
 *
 * <p>The library is resolved from the {@code NEXUSQ_LIBRARY} environment
 * variable when set, otherwise the system loader default ({@code nexusq}) is
 * used. Build the C SDK first: {@code cargo build -p nexusq-c}.
 */
public final class Nexusq {

    static {
        // Force UTF-8 for JNA string marshalling regardless of the host JVM
        // default charset, matching the C SDK contract.
        System.setProperty("jna.encoding", "UTF-8");
    }

    interface CApi extends Library {
        String nexusq_version();
        String nexusq_backend_name();
        byte nexusq_backend_is_experimental();
        String nexusq_last_error_message();
        int nexusq_vault_create(String path, String password, String label);
        int nexusq_vault_format_version(String path);
    }

    private static final String RUNTIME_VERSION = "4.1.0";

    static final CApi C = Native.load(resolveLibrary(), CApi.class);

    private static String resolveLibrary() {
        String override = System.getenv("NEXUSQ_LIBRARY");
        if (override != null && !override.isBlank()) return override;
        RuntimeAsset asset = runtimeAsset();
        Path cache = Path.of(System.getProperty("user.home"), ".cache", "nexusq", RUNTIME_VERSION);
        Path library = cache.resolve(asset.localName);
        Path digestFile = cache.resolve(asset.localName + ".sha256");
        try {
            Files.createDirectories(cache);
            if (Files.isRegularFile(library) && Files.isRegularFile(digestFile)) {
                String expected = Files.readString(digestFile, StandardCharsets.US_ASCII).trim();
                if (expected.equals(sha256(Files.readAllBytes(library)))) return library.toAbsolutePath().toString();
            }
            String base = "https://github.com/lecodev-26/nexus-q/releases/download/v" + RUNTIME_VERSION + "/";
            HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build();
            HttpResponse<byte[]> sums = get(client, base + "NATIVE-RUNTIME-SHA256SUMS");
            String expected = new String(sums.body(), StandardCharsets.UTF_8).lines()
                    .filter(line -> line.trim().endsWith("  " + asset.assetName))
                    .map(line -> line.trim().split("\\s+")[0]).findFirst()
                    .orElseThrow(() -> new IOException("No release checksum found for " + asset.assetName));
            HttpResponse<byte[]> binary = get(client, base + asset.assetName);
            String actual = sha256(binary.body());
            if (!actual.equalsIgnoreCase(expected)) throw new IOException("SHA-256 mismatch for " + asset.assetName);
            Path temporary = cache.resolve(asset.localName + ".download");
            Files.write(temporary, binary.body());
            try {
                Files.move(temporary, library, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, library, StandardCopyOption.REPLACE_EXISTING);
            }
            Files.writeString(digestFile, actual + "\n", StandardCharsets.US_ASCII);
            return library.toAbsolutePath().toString();
        } catch (IOException | InterruptedException | NoSuchAlgorithmException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new IllegalStateException("Unable to obtain a verified NEXUS-Q " + RUNTIME_VERSION
                    + " native runtime. Set NEXUSQ_LIBRARY to a compatible library path. " + e.getMessage(), e);
        }
    }

    private static HttpResponse<byte[]> get(HttpClient client, String url)
            throws IOException, InterruptedException {
        HttpResponse<byte[]> response = client.send(
                HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) throw new IOException("HTTP " + response.statusCode() + " downloading " + url);
        return response;
    }

    private static String sha256(byte[] bytes) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte value : digest) hex.append(String.format("%02x", value & 0xff));
        return hex.toString();
    }

    private static RuntimeAsset runtimeAsset() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();
        if (os.contains("linux") && isMuslLinux())
            throw new IllegalStateException("Prebuilt NEXUS-Q Linux runtimes require glibc, not musl/Alpine. Set NEXUSQ_LIBRARY to a compatible build.");
        if (os.contains("linux") && (arch.equals("amd64") || arch.equals("x86_64")))
            return new RuntimeAsset("nexusq-sdk-runtime-linux-x64.so", "libnexusq.so");
        if (os.contains("linux") && (arch.equals("aarch64") || arch.equals("arm64")))
            return new RuntimeAsset("nexusq-sdk-runtime-linux-arm64.so", "libnexusq.so");
        if (os.contains("mac") && (arch.equals("aarch64") || arch.equals("arm64")))
            return new RuntimeAsset("nexusq-sdk-runtime-macos-arm64.dylib", "libnexusq.dylib");
        if (os.contains("win") && (arch.equals("amd64") || arch.equals("x86_64")))
            return new RuntimeAsset("nexusq-sdk-runtime-windows-x64.dll", "nexusq.dll");
        throw new IllegalStateException("No prebuilt NEXUS-Q runtime for " + os + "/" + arch
                + ". Set NEXUSQ_LIBRARY to a compatible library path.");
    }

    private static boolean isMuslLinux() {
        return Files.exists(Path.of("/lib/ld-musl-x86_64.so.1"))
                || Files.exists(Path.of("/lib/ld-musl-aarch64.so.1"))
                || Files.exists(Path.of("/lib/ld-musl-armhf.so.1"));
    }

    private static final class RuntimeAsset {
        final String assetName;
        final String localName;
        RuntimeAsset(String assetName, String localName) {
            this.assetName = assetName;
            this.localName = localName;
        }
    }

    private Nexusq() {}

    /** Returns the library version string. */
    public static String version() {
        return C.nexusq_version();
    }

    /** Reports the provider compiled into the loaded library; this does not switch providers. */
    public static BackendInfo backendInfo() {
        String name = C.nexusq_backend_name();
        return new BackendInfo(name, C.nexusq_backend_is_experimental() != 0, name.equals("native-experimental"));
    }

    public static final class BackendInfo {
        private final String name;
        private final boolean experimental;
        private final boolean nativeAvailable;

        public BackendInfo(String name, boolean experimental, boolean nativeAvailable) {
            this.name = name;
            this.experimental = experimental;
            this.nativeAvailable = nativeAvailable;
        }

        public String name() { return name; }
        public boolean experimental() { return experimental; }
        public boolean nativeAvailable() { return nativeAvailable; }
    }

    /** Returns the last error message on the calling thread, or null. */
    public static String lastError() {
        return C.nexusq_last_error_message();
    }

    /** A NEXUS-Q vault created on disk. */
    public static final class Vault {
        /** Path of the vault file on disk. */
        public final String path;
        /** Format version byte of the vault (currently 1). */
        public final int formatVersion;

        private Vault(String path, int formatVersion) {
            this.path = path;
            this.formatVersion = formatVersion;
        }

        /**
         * Creates a new vault at {@code path} with the given {@code password}.
         * {@code label} is optional and may be null.
         *
         * @throws NexusqException when the operation fails; the message is
         *     borrowed from the library's last error.
         */
        public static Vault create(String path, String password, String label) {
            int rc = C.nexusq_vault_create(path, password, label);
            if (rc != 0) {
                throw new NexusqException(lastError());
            }
            int formatVersion = C.nexusq_vault_format_version(path);
            if (formatVersion < 0) {
                throw new NexusqException(lastError());
            }
            return new Vault(path, formatVersion);
        }
    }
}

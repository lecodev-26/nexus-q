package io.github.lecodev26.nexusq;

import com.sun.jna.Library;
import com.sun.jna.Native;

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

    static final CApi C = Native.load(
            System.getenv().getOrDefault("NEXUSQ_LIBRARY", "nexusq"), CApi.class);

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

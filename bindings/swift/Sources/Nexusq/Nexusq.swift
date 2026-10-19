import CNexusq

/// NEXUS-Q Swift bindings.
///
/// This is a thin wrapper over the stable C SDK. It does not reimplement
/// cryptography or business logic; every operation delegates to libnexusq.
/// The library is loaded by the OS dynamic linker (link `nexusq`); the
/// `NEXUSQ_LIBRARY` environment variable is not used by this binding.
public enum Nexusq {

    /// Returns the library version string.
    public static func version() -> String {
        String(cString: nexusq_version())
    }

    /// Reports the provider compiled into the linked library; this does not switch providers.
    public static func backendInfo() -> BackendInfo {
        let name = String(cString: nexusq_backend_name())
        return BackendInfo(name: name, experimental: nexusq_backend_is_experimental() != 0, nativeAvailable: name == "native-experimental")
    }

    public struct BackendInfo: Equatable {
        public let name: String
        public let experimental: Bool
        public let nativeAvailable: Bool
    }

    /// Returns the last error message on the calling thread, or nil.
    /// The message is borrowed from the library and remains valid until the
    /// next NEXUS-Q call on the same thread.
    public static func lastError() -> String? {
        let message = nexusq_last_error_message()
        return message == nil ? nil : String(cString: message!)
    }

    /// A NEXUS-Q vault created on disk.
    public struct Vault: Equatable {
        /// Path of the vault file on disk.
        public let path: String
        /// Format version byte of the vault (currently 1).
        public let formatVersion: Int32

        /// Creates a new vault at `path` with the given `password`.
        /// `label` is optional and may be nil.
        ///
        /// Throws `NexusqError` when the operation fails; the message is
        /// borrowed from the library's last error.
        public static func create(_ path: String, password: String, label: String? = nil) throws -> Vault {
            let rc = path.withCString { pathC in
                password.withCString { passwordC in
                    label.map { value in
                        value.withCString { labelC in
                            nexusq_vault_create(pathC, passwordC, labelC)
                        }
                    } ?? nexusq_vault_create(pathC, passwordC, nil)
                }
            }
            guard rc == 0 else {
                throw NexusqError(lastError())
            }
            let formatVersion = path.withCString { nexusq_vault_format_version($0) }
            guard formatVersion >= 0 else {
                throw NexusqError(lastError())
            }
            return Vault(path: path, formatVersion: formatVersion)
        }
    }

    /// Error raised when a NEXUS-Q operation fails.
    public struct NexusqError: Error, CustomStringConvertible {
        public let message: String?

        init(_ message: String?) {
            self.message = message
        }

        public var description: String {
            message ?? "NEXUS-Q operation failed"
        }
    }
}

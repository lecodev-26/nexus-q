import CryptoKit
import Darwin
import Foundation

/// NEXUS-Q Swift bindings.
///
/// This is a thin wrapper over the stable C SDK. It does not reimplement
/// cryptography or business logic; every operation delegates to libnexusq.
/// Published macOS ARM64 releases download and verify the matching RustCrypto
/// runtime automatically. `NEXUSQ_LIBRARY` overrides the resolver for custom builds.
public enum Nexusq {

    /// Returns the library version string.
    public static func version() -> String {
        String(cString: NativeRuntime.version())
    }

    /// Reports the provider compiled into the linked library; this does not switch providers.
    public static func backendInfo() -> BackendInfo {
        let name = String(cString: NativeRuntime.backendName())
        return BackendInfo(name: name, experimental: NativeRuntime.backendExperimental() != 0, nativeAvailable: name == "native-experimental")
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
        let message = NativeRuntime.lastError()
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
                            NativeRuntime.vaultCreate(pathC, passwordC, labelC)
                        }
                    } ?? NativeRuntime.vaultCreate(pathC, passwordC, nil)
                }
            }
            guard rc == 0 else {
                throw NexusqError(lastError())
            }
            let formatVersion = path.withCString { NativeRuntime.vaultFormatVersion($0) }
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


/// Loads the stable C ABI at runtime so consumers do not need a system-wide
/// library installation. The downloaded binary is version-matched and verified
/// against the release SHA-256 manifest before dlopen.
private enum NativeRuntime {
    private static let runtimeVersion = "4.1.0"
    private static let assetName = "nexusq-sdk-runtime-macos-arm64.dylib"
    private static let localName = "libnexusq.dylib"

    private final class ResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Result<Data, Error>?
        func set(_ value: Result<Data, Error>) { lock.lock(); stored = value; lock.unlock() }
        func get() -> Result<Data, Error>? { lock.lock(); defer { lock.unlock() }; return stored }
    }

    private static let handle: UnsafeMutableRawPointer = {
        do {
            let path = try resolveLibraryPath()
            guard let handle = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
                let detail = dlerror().map { String(cString: $0) } ?? "unknown dynamic-loader error"
                throw RuntimeError("Unable to load \(path): \(detail)")
            }
            return handle
        } catch {
            fatalError("NEXUS-Q native runtime unavailable: \(error). Set NEXUSQ_LIBRARY to a compatible library path.")
        }
    }()

    private struct RuntimeError: LocalizedError {
        let message: String
        init(_ message: String) { self.message = message }
        var errorDescription: String? { message }
    }

    private static func resolveLibraryPath() throws -> String {
        if let override = ProcessInfo.processInfo.environment["NEXUSQ_LIBRARY"], !override.isEmpty {
            return override
        }
        #if arch(arm64)
        #else
        throw RuntimeError("Prebuilt Swift runtime is currently available only for macOS ARM64")
        #endif

        let cache = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".cache/nexusq/\(runtimeVersion)/\(assetName)", isDirectory: true)
        try FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true)
        let library = cache.appendingPathComponent(localName)
        let digestFile = cache.appendingPathComponent(localName + ".sha256")
        if let expected = try? String(contentsOf: digestFile, encoding: .ascii).trimmingCharacters(in: .whitespacesAndNewlines),
           let bytes = try? Data(contentsOf: library), checksum(bytes) == expected {
            return library.path
        }

        let base = URL(string: "https://github.com/lecodev-26/nexus-q/releases/download/v\(runtimeVersion)/")!
        let checksums = try download(base.appendingPathComponent("NATIVE-RUNTIME-SHA256SUMS"))
        let checksumText = String(decoding: checksums, as: UTF8.self)
        guard let line = checksumText.split(separator: "\n").first(where: { String($0).trimmingCharacters(in: .whitespaces).hasSuffix("  \(assetName)") }),
              let expected = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) else {
            throw RuntimeError("No published SHA-256 checksum for \(assetName)")
        }
        let bytes = try download(base.appendingPathComponent(assetName))
        let actual = checksum(bytes)
        guard actual == expected.lowercased() else { throw RuntimeError("SHA-256 mismatch for \(assetName); refusing to load an unverified runtime") }
        let temporary = cache.appendingPathComponent(localName + ".download")
        try bytes.write(to: temporary, options: .atomic)
        if FileManager.default.fileExists(atPath: library.path) { try FileManager.default.removeItem(at: library) }
        try FileManager.default.moveItem(at: temporary, to: library)
        try (actual + "\n").write(to: digestFile, atomically: true, encoding: .ascii)
        return library.path
    }

    private static func download(_ url: URL) throws -> Data {
        let semaphore = DispatchSemaphore(value: 0)
        let result = ResultBox()
        URLSession.shared.dataTask(with: url) { data, response, error in
            defer { semaphore.signal() }
            if let error { result.set(.failure(error)); return }
            guard let response = response as? HTTPURLResponse, response.statusCode == 200, let data else {
                result.set(.failure(RuntimeError("HTTP response was not successful for \(url)")))
                return
            }
            result.set(.success(data))
        }.resume()
        guard semaphore.wait(timeout: .now() + 60) == .success else { throw RuntimeError("Timed out downloading \(url)") }
        guard let result = result.get() else { throw RuntimeError("Download returned no data for \(url)") }
        return try result.get()
    }

    private static func checksum(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", Int($0)) }.joined()
    }

    private static func function<T>(_ name: String, as type: T.Type) -> T {
        guard let symbol = dlsym(handle, name) else {
            let detail = dlerror().map { String(cString: $0) } ?? "symbol not found"
            fatalError("NEXUS-Q runtime is missing \(name): \(detail)")
        }
        return unsafeBitCast(symbol, to: type)
    }

    private typealias StringFn = @convention(c) () -> UnsafePointer<CChar>?
    private typealias ByteFn = @convention(c) () -> UInt8
    private typealias VaultCreateFn = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Int32
    private typealias VaultVersionFn = @convention(c) (UnsafePointer<CChar>?) -> Int32

    static func version() -> UnsafePointer<CChar> { function("nexusq_version", as: StringFn.self)()! }
    static func backendName() -> UnsafePointer<CChar> { function("nexusq_backend_name", as: StringFn.self)()! }
    static func backendExperimental() -> UInt8 { function("nexusq_backend_is_experimental", as: ByteFn.self)() }
    static func lastError() -> UnsafePointer<CChar>? { function("nexusq_last_error_message", as: StringFn.self)() }
    static func vaultCreate(_ path: UnsafePointer<CChar>, _ password: UnsafePointer<CChar>, _ label: UnsafePointer<CChar>?) -> Int32 {
        function("nexusq_vault_create", as: VaultCreateFn.self)(path, password, label)
    }
    static func vaultFormatVersion(_ path: UnsafePointer<CChar>) -> Int32 {
        function("nexusq_vault_format_version", as: VaultVersionFn.self)(path)
    }
}

import XCTest

@testable import Nexusq

final class NexusqTests: XCTestCase {
    func testVersionIsReported() {
        XCTAssertTrue(Nexusq.version().hasPrefix("4.1.1"))
    }

    func testBackendMetadataIsConsistent() {
        let info = Nexusq.backendInfo()
        XCTAssertFalse(info.name.isEmpty)
        XCTAssertEqual(info.nativeAvailable, info.name == "native-experimental")
        XCTAssertEqual(info.experimental, info.nativeAvailable)
    }

    func testVaultCreateRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nexusq_swift_test_\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("vault.nqv").path

        let vault = try Nexusq.Vault.create(path, password: "swift-test", label: "swift-test")
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        XCTAssertEqual(vault.path, path)
        XCTAssertEqual(vault.formatVersion, 1)
    }

    func testVaultCreateWithoutLabel() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nexusq_swift_test_\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let vault = try Nexusq.Vault.create(
            dir.appendingPathComponent("vault.nqv").path, password: "swift-test")
        XCTAssertEqual(vault.formatVersion, 1)
    }

    func testFailuresCarryLibraryMessages() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nexusq_swift_test_\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let missing = dir.appendingPathComponent("no")
            .appendingPathComponent("parent")
            .appendingPathComponent("v.nqv").path

        XCTAssertThrowsError(try Nexusq.Vault.create(missing, password: "x")) { error in
            guard let nexusqError = error as? Nexusq.NexusqError else {
                return XCTFail("unexpected error type")
            }
            XCTAssertNotNil(nexusqError.message)
            XCTAssertNotEqual(nexusqError.message, "")
        }
    }
}

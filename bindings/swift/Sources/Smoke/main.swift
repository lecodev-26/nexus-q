import Foundation

import Nexusq

// Smoke test for the NEXUS-Q Swift SDK.
//
// Run from the repository root with the C SDK on the loader path:
//   LD_LIBRARY_PATH=target/debug swift run -c release Smoke

func fail(_ message: String) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(1)
}

print("nexusq version: \(Nexusq.version())")

let dir = FileManager.default.temporaryDirectory
    .appendingPathComponent("nexusq_swift_smoke_\(getpid())", isDirectory: true)
try? FileManager.default.removeItem(at: dir)
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
let path = dir.appendingPathComponent("vault.nqv").path

do {
    let vault = try Nexusq.Vault.create(path, password: "swift-test", label: "swift-smoke")

    guard FileManager.default.fileExists(atPath: path) else { fail("vault file was not created") }
    guard vault.path == path else { fail("vault.path does not match input") }
    guard vault.formatVersion == 1 else { fail("format_version must be 1, got \(vault.formatVersion)") }

    print("vault created at \(vault.path)")
    print("vault format version: \(vault.formatVersion)")
} catch let error as Nexusq.NexusqError {
    fail("\(error)")
} catch {
    fail("\(error)")
}

var raised = false
do {
    _ = try Nexusq.Vault.create(
        dir.appendingPathComponent("no").appendingPathComponent("parent").appendingPathComponent("v.nqv").path,
        password: "x")
    fail("creating a vault under a missing directory must fail")
} catch let error as Nexusq.NexusqError {
    raised = !error.message!.isEmpty
} catch {
    fail("unexpected error type: \(error)")
}
guard raised else { fail("error without message") }

print("error propagation: ok")
print("smoke test passed")

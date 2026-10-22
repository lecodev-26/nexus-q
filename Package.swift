// swift-tools-version:5.9
import PackageDescription

// Root Swift Package manifest for NEXUS-Q.
// Keep the root package aligned with bindings/swift/Package.swift so SwiftPM
// consumers can use the repository root without a stale system-library target.
// The current binding loads the version-matched C ABI runtime dynamically.
let package = Package(
    name: "nexusq",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "Nexusq", targets: ["Nexusq"]),
        .executable(name: "Smoke", targets: ["Smoke"]),
    ],
    targets: [
        .target(
            name: "Nexusq",
            path: "bindings/swift/Sources/Nexusq"
        ),
        .testTarget(
            name: "NexusqTests",
            dependencies: ["Nexusq"],
            path: "bindings/swift/Tests/NexusqTests"
        ),
        .executableTarget(
            name: "Smoke",
            dependencies: ["Nexusq"],
            path: "bindings/swift/Sources/Smoke"
        ),
    ]
)

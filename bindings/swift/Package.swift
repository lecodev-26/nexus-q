// swift-tools-version:5.9
import PackageDescription

/// NEXUS-Q Swift bindings.
///
/// Thin wrapper over the stable C SDK (`libnexusq`). Published macOS ARM64
/// releases download and verify the version-matched runtime automatically.
let package = Package(
    name: "nexusq",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "Nexusq", targets: ["Nexusq"]),
        .executable(name: "Smoke", targets: ["Smoke"]),
    ],
    targets: [
        .target(
            name: "Nexusq"
        ),
        .testTarget(
            name: "NexusqTests",
            dependencies: ["Nexusq"]
        ),
        .executableTarget(
            name: "Smoke",
            dependencies: ["Nexusq"],
            path: "Sources/Smoke"
        ),
    ]
)

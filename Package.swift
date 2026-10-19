// swift-tools-version:5.9
import PackageDescription

// Root Swift Package manifest for NEXUS-Q.
//
// Swift Package Manager resolves a repository dependency against the
// Package.swift at its root, so this manifest re-exports the binding that
// lives under bindings/swift. It is intentionally identical in structure to
// bindings/swift/Package.swift; the two manifests describe the same targets.
//
// The binding is a thin wrapper over the C SDK (`libnexusq`): build and
// install the C library first (`cargo build -p nexusq-c`) so that both the
// linker and the dynamic loader can find it.
let package = Package(
    name: "nexusq",
    products: [
        .library(name: "Nexusq", targets: ["Nexusq"]),
    ],
    targets: [
        .systemLibrary(
            name: "CNexusq",
            path: "bindings/swift/Sources/CNexusq"
        ),
        .target(
            name: "Nexusq",
            dependencies: ["CNexusq"],
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

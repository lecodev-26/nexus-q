// swift-tools-version:5.9
import PackageDescription

/// NEXUS-Q Swift bindings.
///
/// Thin wrapper over the stable C SDK (`libnexusq`). Build and install the C
/// library first: `cargo build -p nexusq-c`, then point the dynamic loader at
/// it (for example `LD_LIBRARY_PATH=target/debug`). The C SDK surface is
/// declared through the `CNexusq` system-library target, which links
/// `nexusq` and re-exports the repository header.
let package = Package(
    name: "nexusq",
    products: [
        .library(name: "Nexusq", targets: ["Nexusq"]),
        .executable(name: "Smoke", targets: ["Smoke"]),
    ],
    targets: [
        .systemLibrary(
            name: "CNexusq",
            path: "Sources/CNexusq"
        ),
        .target(
            name: "Nexusq",
            dependencies: ["CNexusq"]
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

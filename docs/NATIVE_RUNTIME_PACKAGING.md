# Native runtime packaging and SDK loading

## Provider and trust contract

The distributable SDK runtime is built with the default Cargo feature set and
must report `rustcrypto` with `experimental=false`. The separately maintained
`native-runtime.yml` workflow builds the opt-in native backend for portability
and C ABI testing; its experimental artifacts are **not** the runtime assets
published for ordinary SDK installation. SDK packages must never silently
switch users to the experimental provider.

Release assets are version-matched to the SDK release and include
`NATIVE-RUNTIME-SHA256SUMS`. Downloading SDKs verify the SHA-256 of the binary
before loading it. The checksum and binary are delivered by the same GitHub
release over HTTPS; this detects accidental corruption and tampering in
transit, but is not a substitute for independent security review or a separate
signing trust root. The native backend remains experimental and opt-in.

## Prebuilt target matrix

| Runtime asset | Target | ABI / limitation |
|---|---|---|
| `nexusq-sdk-runtime-linux-x64.so` | `x86_64-unknown-linux-gnu` | glibc 2.35+; not musl |
| `nexusq-sdk-runtime-linux-arm64.so` | `aarch64-unknown-linux-gnu` | glibc 2.39+; not musl |
| `nexusq-sdk-runtime-macos-arm64.dylib` | `aarch64-apple-darwin` | macOS ARM64 |
| `nexusq-sdk-runtime-windows-x64.dll` | `x86_64-pc-windows-msvc` | Windows x64 / MSVC ABI |

No prebuilt artifact is claimed for Linux musl, macOS Intel, Windows ARM64, or
other targets. Those targets must fail with an actionable message or use an
explicit compatible `NEXUSQ_LIBRARY` override. The override is an advanced
escape hatch, not the standard installation flow.

## SDK loading status

- **Python:** the PyO3/maturin wheel carries the Rust core and is tested by
  installing the wheel into a clean environment without Rust.
- **TypeScript/Node.js:** install-time downloader selects a supported asset,
  verifies the release checksum, and caches the runtime in the installed SDK.
- **Java and Kotlin:** JNA loaders fetch and verify the matching asset on first
  use, then cache it under `~/.cache/nexusq/<version>/<runtime-asset>` to avoid cross-architecture cache collisions.
- **Ruby and PHP:** FFI loaders fetch and verify the matching asset on first
  use, then cache it under a per-user, versioned, target-specific cache directory.
- **.NET:** the NuGet publishing workflow stages all four assets under
  `runtimes/<rid>/native/`, so the normal .NET native resolver can select the
  current RID. CI installs the packed package into a clean consumer and loads
  the library without `NEXUSQ_LIBRARY`.
- **C/C++:** versioned release archives contain the library and public header;
  consumers still need the ecosystem's normal linker/runtime configuration.
- **Go, Dart, and Swift:** automatic acquisition/resolution is not yet complete.
  Their current cgo, Dart FFI, and SwiftPM system-library integration still
  requires a compatible library to be built/installed or explicitly located.
  These SDKs remain open work for issue #61.

## Release procedure

The release workflow builds default-provider runtime artifacts on their native
runners, validates the C ABI metadata, creates versioned archives and direct
per-platform runtime assets, computes SHA-256 checksums, and attaches the
assets to the matching GitHub release. The NuGet publishing workflow builds the
same runtime matrix before packaging, rather than relying on stale or unrelated
artifacts. Do not publish an SDK version unless the corresponding runtime assets
for its declared targets exist and the clean-install smoke tests pass.

# NEXUS-Q Go SDK

Go bindings for NEXUS-Q. A thin wrapper over the [C SDK](../../crates/nexusq-c)
built with `cgo`. It does not reimplement anything: every call goes
through `libnexusq`.

## Requirements

- Go 1.21 or newer.
- On supported published releases, the helper script downloads the matching
  RustCrypto runtime and header, verifies the release and archive checksums,
  and configures cgo for Linux x64/ARM64 glibc and macOS ARM64. Go consumers do
  not need Rust; the downloaded runtime is cached under `~/.cache/nexusq`.
- Windows, musl/Alpine, macOS Intel, and other unsupported targets still need a
  compatible library built/installed separately.

## Usage

```go
package main

import (
    "fmt"
    "github.com/lecodev-26/nexusq/bindings/go/nexusq"
)

func main() {
    fmt.Println("nexusq version:", nexusq.Version())

    vault, err := nexusq.CreateVault("my.nqv", "password", "my-label")
    if err != nil {
        panic(err)
    }
    fmt.Println("vault created at", vault.Path())
    fmt.Println("format version:", vault.FormatVersion())
}
```

Build and run (the first call downloads and verifies the runtime):

```bash
cd bindings/go
./scripts/with-runtime.sh go run ./examples/smoke
cd nexusq
../scripts/with-runtime.sh go test ./...
```

For an advanced local build, set `CGO_CFLAGS`, `CGO_LDFLAGS`, and the platform
loader path explicitly as described below.

The helper sets `CGO_CFLAGS`, `CGO_LDFLAGS`, and `LD_LIBRARY_PATH` (or
`DYLD_LIBRARY_PATH`) for the child command. When you vendor the Go module
elsewhere, run the helper from the checkout or set those variables yourself.

What is available

· nexusq.Version() — returns the library version.
· nexusq.Vault:
  · nexusq.CreateVault(path, password, label) (*Vault, error)
  · vault.Path() string
  · vault.FormatVersion() int

More operations land as the C SDK grows.

Testing

The smoke test lives at examples/smoke/main.go. Build and run it
with:

```bash
cd bindings/go
./scripts/with-runtime.sh go run ./examples/smoke
```

Expected output:

```
nexusq version: 0.1.0
vault created at /home/you/nexusq_go_smoke.nqv
vault format version: 1
cleaned up
```


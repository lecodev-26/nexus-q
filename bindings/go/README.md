# NEXUS-Q Go SDK

The Go SDK calls the stable `libnexusq` C ABI through a pure-Go dynamic loader. On first use it downloads the version-matched runtime, verifies its SHA-256 checksum, checks that the loaded provider is the default RustCrypto backend, and caches the runtime under the operating system's user cache directory.

## Requirements

- Go 1.22 or newer.
- A supported target and network access on first use; `curl`, cgo, a C compiler, and manual linker configuration are not required.
- Prebuilt targets: Linux x64/ARM64 with glibc, macOS ARM64, and Windows x64. Linux musl/Alpine, macOS Intel, Windows ARM64, and other targets require a compatible custom runtime.

## Install and use

```bash
go get github.com/lecodev-26/nexus-q/bindings/go/nexusq
```

```go
package main

import (
    "fmt"
    "github.com/lecodev-26/nexus-q/bindings/go/nexusq"
)

func main() {
    fmt.Println("nexusq version:", nexusq.Version())
    vault, err := nexusq.CreateVault("my.nqv", "password", "my-label")
    if err != nil { panic(err) }
    fmt.Println("vault created at", vault.Path())
    fmt.Println("format version:", vault.FormatVersion())
}
```

The first call downloads and verifies the runtime automatically. Subsequent calls use the versioned local cache. `NEXUSQ_LIBRARY` is an advanced override for development or offline testing; ordinary consumers should not need it.

## API

- `nexusq.Version() string`
- `nexusq.CryptoBackendInfo() nexusq.BackendInfo`
- `nexusq.CreateVault(path, password, label) (*nexusq.Vault, error)`
- `vault.Path() string`
- `vault.FormatVersion() int`

## Development tests

The repository CI builds `libnexusq` and sets `NEXUSQ_LIBRARY` to that local build so tests do not depend on a not-yet-published release asset. The legacy `scripts/with-runtime.sh` is retained for older cgo-based workflows but is not required by the current SDK implementation.

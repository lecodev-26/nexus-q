# NEXUS-Q Go SDK

Go bindings for NEXUS-Q. A thin wrapper over the [C SDK](../../crates/nexusq-c)
built with `cgo`. It does not reimplement anything: every call goes
through `libnexusq`.

## Requirements

- Go 1.21 or newer.
- The C SDK built (`cargo build -p nexusq-c`).
- The directory holding `libnexusq.so` in `LD_LIBRARY_PATH` at
  runtime.

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

Build and run:

```bash
LD_LIBRARY_PATH=/path/to/nexusq/target/debug \
go run ./your_program
```

The #cgo directives in nexusq/nexusq.go point at the C SDK's
include directory and the Cargo target/debug directory relative to
this repository. When you vendor the Go module elsewhere, adjust
those paths or set CGO_CFLAGS and CGO_LDFLAGS.

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
LD_LIBRARY_PATH="$(pwd)/../../target/debug" \
go run ./examples/smoke
```

Expected output:

```
nexusq version: 0.1.0
vault created at /home/you/nexusq_go_smoke.nqv
vault format version: 1
cleaned up
```


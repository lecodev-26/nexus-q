// Smoke test for the Go SDK.
//
// Build:
//   cd bindings/go/examples/smoke
//   CGO_CFLAGS="-I $(pwd)/../../../../crates/nexusq-c/include" \
//   CGO_LDFLAGS="-L $(pwd)/../../../../target/debug -lnexusq" \
//   go run main.go
//
// At runtime, LD_LIBRARY_PATH must include the directory holding
// libnexusq.so.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lecodev-26/nexus-q/bindings/go/nexusq"
)

func main() {
	fmt.Println("nexusq version:", nexusq.Version())
	provider := nexusq.CryptoBackendInfo()
	if provider.Name == "" || provider.NativeAvailable != (provider.Name == "native-experimental") || provider.Experimental != provider.NativeAvailable {
		fmt.Fprintln(os.Stderr, "invalid backend metadata:", provider)
		os.Exit(1)
	}
	fmt.Println("PQC backend:", provider.Name)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot find HOME:", err)
		os.Exit(1)
	}

	path := filepath.Join(home, "nexusq_go_smoke.nqv")
	os.Remove(path)

	vault, err := nexusq.CreateVault(path, "go-test", "go-smoke")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Remove(path)
		os.Exit(1)
	}
	fmt.Println("vault created at", vault.Path())
	fmt.Println("vault format version:", vault.FormatVersion())

	os.Remove(path)
	fmt.Println("cleaned up")
}

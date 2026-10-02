// Package nexusq provides Go bindings for NEXUS-Q.
//
// It is a thin wrapper over the C SDK. Every exported function and
// type delegates to libnexusq; no cryptography and no business logic
// live here.
//
// Build: the C SDK must be built and available. Set CGO_CFLAGS and
// CGO_LDFLAGS, or place libnexusq where the linker can find it:
//
//     CGO_CFLAGS="-I $(pwd)/crates/nexusq-c/include" \
//     CGO_LDFLAGS="-L $(pwd)/target/debug -lnexusq" \
//     go build
//
// At runtime, LD_LIBRARY_PATH must include the directory holding
// libnexusq.so.
package nexusq

/*
#cgo CFLAGS: -I${SRCDIR}/../../../crates/nexusq-c/include
#cgo LDFLAGS: -L${SRCDIR}/../../../target/debug -lnexusq
#include <stdlib.h>
#include "nexusq.h"
*/
import "C"

import (
"errors"
"unsafe"
)

// Version returns the library version.
func Version() string {
return C.GoString(C.nexusq_version())
}

// lastError returns the last error message, if any.
func lastError() error {
msg := C.nexusq_last_error_message()
if msg == nil {
return errors.New("unknown NEXUS-Q error")
}
return errors.New(C.GoString(msg))
}

// Vault is a handle to a vault file on disk.
type Vault struct {
path          string
formatVersion int
}

// CreateVault creates a new vault at path with the given password and
// label. Pass an empty string for label if none is wanted.
func CreateVault(path, password, label string) (*Vault, error) {
cPath := C.CString(path)
cPassword := C.CString(password)
defer C.free(unsafe.Pointer(cPath))
defer C.free(unsafe.Pointer(cPassword))

var cLabel *C.char
if label != "" {
cLabel = C.CString(label)
defer C.free(unsafe.Pointer(cLabel))
}

rc := C.nexusq_vault_create(cPath, cPassword, cLabel)
if rc != 0 {
return nil, lastError()
}

version := C.nexusq_vault_format_version(cPath)
if version < 0 {
return nil, lastError()
}

return &Vault{path: path, formatVersion: int(version)}, nil
}

// Path returns the path of the vault file.
func (v *Vault) Path() string {
return v.path
}

// FormatVersion returns the format version of the vault file.
func (v *Vault) FormatVersion() int {
return v.formatVersion
}

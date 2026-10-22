// Package nexusq provides Go bindings for NEXUS-Q.
//
// The SDK downloads and verifies the version-matched native runtime on first
// use for supported targets. No C compiler, cgo flags, or manual library path
// is required. Set NEXUSQ_LIBRARY only to override the resolver for development.
package nexusq

import (
	"errors"
	"unsafe"
)

var (
	_nativeLibrary             uintptr
	_nativeVersion             func() unsafe.Pointer
	_nativeBackendName         func() unsafe.Pointer
	_nativeBackendExperimental func() uint8
	_nativeLastError           func() unsafe.Pointer
	_nativeVaultCreate         func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer) int32
	_nativeVaultFormatVersion  func(unsafe.Pointer) int32
)

func init() {
	var err error
	_nativeLibrary, err = openNativeLibrary(resolveRuntime())
	if err != nil {
		panic("NEXUS-Q: unable to load native runtime: " + err.Error())
	}
	registerNativeFunctions(_nativeLibrary)
	if CryptoBackendInfo().Name != "rustcrypto" || CryptoBackendInfo().Experimental {
		panic("NEXUS-Q: refusing a runtime that is not the default RustCrypto provider")
	}
}

func cString(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}
	n := 0
	for *(*byte)(unsafe.Add(ptr, n)) != 0 {
		n++
	}
	return unsafe.String((*byte)(ptr), n)
}

func cBuffer(value string) []byte { return append([]byte(value), 0) }

// Version returns the loaded library version.
func Version() string { return cString(_nativeVersion()) }

// BackendInfo reports the provider compiled into the loaded library; it never switches providers.
type BackendInfo struct {
	Name            string
	Experimental    bool
	NativeAvailable bool
}

// CryptoBackendInfo reports the provider compiled into libnexusq.
func CryptoBackendInfo() BackendInfo {
	name := cString(_nativeBackendName())
	experimental := _nativeBackendExperimental() != 0
	return BackendInfo{Name: name, Experimental: experimental, NativeAvailable: name == "native-experimental"}
}

func lastError() error {
	msg := cString(_nativeLastError())
	if msg == "" {
		return errors.New("unknown NEXUS-Q error")
	}
	return errors.New(msg)
}

// Vault is a handle to a vault file on disk.
type Vault struct {
	path          string
	formatVersion int
}

// CreateVault creates a new vault at path with the given password and label.
// Pass an empty label when no label is required.
func CreateVault(path, password, label string) (*Vault, error) {
	cPath, cPassword := cBuffer(path), cBuffer(password)
	var labelPtr unsafe.Pointer
	var cLabel []byte
	if label != "" {
		cLabel = cBuffer(label)
		labelPtr = unsafe.Pointer(&cLabel[0])
	}
	rc := _nativeVaultCreate(unsafe.Pointer(&cPath[0]), unsafe.Pointer(&cPassword[0]), labelPtr)
	if rc != 0 {
		return nil, lastError()
	}
	version := _nativeVaultFormatVersion(unsafe.Pointer(&cPath[0]))
	if version < 0 {
		return nil, lastError()
	}
	return &Vault{path: path, formatVersion: int(version)}, nil
}

// Path returns the path of the vault file.
func (v *Vault) Path() string { return v.path }

// FormatVersion returns the vault format version.
func (v *Vault) FormatVersion() int { return v.formatVersion }

//go:build !windows

package nexusq

import "github.com/ebitengine/purego"

func openNativeLibrary(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}

func registerNativeFunctions(handle uintptr) {
	purego.RegisterLibFunc(&_nativeVersion, handle, "nexusq_version")
	purego.RegisterLibFunc(&_nativeBackendName, handle, "nexusq_backend_name")
	purego.RegisterLibFunc(&_nativeBackendExperimental, handle, "nexusq_backend_is_experimental")
	purego.RegisterLibFunc(&_nativeLastError, handle, "nexusq_last_error_message")
	purego.RegisterLibFunc(&_nativeVaultCreate, handle, "nexusq_vault_create")
	purego.RegisterLibFunc(&_nativeVaultFormatVersion, handle, "nexusq_vault_format_version")
}

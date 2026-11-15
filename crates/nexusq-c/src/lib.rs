//! C bindings for NEXUS-Q.
//!
//! This crate exposes the library through a C ABI. It is a thin
//! translation layer: every function opens a session, calls into
//! `nexusq-core`, and marshals the result into something C can hold.
//! No cryptography and no business logic live here.
//!
//! The header `nexusq.h` is generated with `cbindgen` from this
//! crate's public items. See `docs/C_SDK.md`.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char};

use nexusq_core::prelude::*;

/// Returns the library version as a static, borrowed NUL-terminated C string.
///
/// The pointer is owned by the library and must not be passed to
/// `nexusq_string_free`.
#[unsafe(no_mangle)]
pub extern "C" fn nexusq_version() -> *const c_char {
    clear_last_error();
    // A static CStr built once at compile time.
    const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr().cast()
}

/// Returns the compile-time cryptographic provider as a static, borrowed C string.
/// The value is either `rustcrypto` or `native-experimental`. The pointer is
/// owned by the library and must not be passed to `nexusq_string_free`.
#[unsafe(no_mangle)]
pub extern "C" fn nexusq_backend_name() -> *const c_char {
    if nexusq_core::backend_info().native_available {
        c"native-experimental".as_ptr()
    } else {
        c"rustcrypto".as_ptr()
    }
}

/// Returns 1 when the compiled provider is experimental, otherwise 0.
#[unsafe(no_mangle)]
pub extern "C" fn nexusq_backend_is_experimental() -> u8 {
    u8::from(nexusq_core::backend_info().experimental)
}

/// Frees a heap-allocated C string explicitly documented as owned by NEXUS-Q.
///
/// Passing null is a no-op. Borrowed/static pointers returned by
/// `nexusq_version`, `nexusq_backend_name`, or `nexusq_last_error_message`
/// must not be passed to this function. No current C ABI function returns an
/// owned heap-allocated string; this function is reserved for future owned
/// string-returning APIs.
///
/// # Safety
///
/// `s` must be null or the exact pointer returned by a NEXUS-Q function whose
/// documentation explicitly states that it returns an owned allocation
/// compatible with `nexusq_string_free`. Passing any borrowed, static,
/// interior, already-freed, or foreign pointer is undefined behavior.
// SAFETY: The public contract above restricts `s` to null or a live allocation
// returned by a NEXUS-Q API that explicitly transfers ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nexusq_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: The caller's contract guarantees that `s` is the exact live
    // allocation returned by a NEXUS-Q owned-string API.
    unsafe {
        let _ = CString::from_raw(s);
    }
}

// Per-thread last error message.
thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> =
        const { std::cell::RefCell::new(None) };
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

fn set_last_error(message: String) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(message).ok();
    });
}

/// Returns a borrowed last-error message on the calling thread, or null.
///
/// The pointer is owned by the library, remains valid only until the next
/// NEXUS-Q call on the same thread, and must not be passed to
/// `nexusq_string_free`.
#[unsafe(no_mangle)]
pub extern "C" fn nexusq_last_error_message() -> *const c_char {
    LAST_ERROR.with(|slot| match slot.borrow().as_ref() {
        Some(s) => s.as_ptr(),
        None => std::ptr::null(),
    })
}

// A helper to read a NUL-terminated C string as a &str slice.
//
// Returns None on null input or invalid UTF-8.
//
// # Safety
//
// `s` must be either null or a valid NUL-terminated C string readable for
// the returned lifetime.
// SAFETY: This helper is unsafe because `CStr::from_ptr` requires the caller
// to guarantee a readable NUL-terminated allocation for the returned lifetime.
unsafe fn cstr_to_str<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }
    // SAFETY: The caller guarantees a valid NUL-terminated C string; null was
    // handled above.
    unsafe { CStr::from_ptr(s) }.to_str().ok()
}

// =============================================================================
// Vault
// =============================================================================

/// Creates a new vault at `path` with the given `password`.
///
/// `path` and `password` must be valid NUL-terminated UTF-8 strings; null
/// pointers are rejected with an error. `label` may be null to create a vault
/// without a label.
///
/// Returns 0 on success and a negative code on failure. On failure,
/// call `nexusq_last_error_message` to retrieve the reason.
///
/// # Safety
///
/// `path`, `password`, and `label` must each be null or point to a readable,
/// NUL-terminated C string. Non-null pointers must remain valid until this call
/// returns; null `path` or `password` is rejected with an error.
// SAFETY: The exported function's contract requires valid NUL-terminated
// pointers (or null for `label`) before any pointer is dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nexusq_vault_create(
    path: *const c_char,
    password: *const c_char,
    label: *const c_char,
) -> i32 {
    clear_last_error();
    // SAFETY: `path` is covered by this function's documented C-string contract.
    let Some(path) = (unsafe { cstr_to_str(path) }) else {
        set_last_error("path is null or not valid UTF-8".into());
        return -1;
    };
    // SAFETY: `password` is covered by this function's documented C-string contract.
    let Some(password) = (unsafe { cstr_to_str(password) }) else {
        set_last_error("password is null or not valid UTF-8".into());
        return -1;
    };
    let label = if label.is_null() {
        None
    } else {
        // SAFETY: The contract requires non-null `label` here to be a valid C string.
        match unsafe { cstr_to_str(label) } {
            Some(s) => Some(s.to_string()),
            None => {
                set_last_error("label is not valid UTF-8".into());
                return -1;
            }
        }
    };

    match Vault::create(path, password.as_bytes(), label) {
        Ok(_) => 0,
        Err(err) => {
            set_last_error(err.to_string());
            -1
        }
    }
}

/// Returns the version byte of the vault at `path`, or a negative
/// code on failure. A null `path` is rejected.
///
/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated C string that
/// remains valid until this call returns.
// SAFETY: The exported function's contract requires `path` to point to a
// readable NUL-terminated C string before it is dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nexusq_vault_format_version(path: *const c_char) -> i32 {
    clear_last_error();
    // SAFETY: `path` is covered by this function's documented C-string contract.
    let Some(path) = (unsafe { cstr_to_str(path) }) else {
        set_last_error("path is null or not valid UTF-8".into());
        return -1;
    };

    match Vault::open(path) {
        Ok(vault) => i32::from(vault.header().version),
        Err(err) => {
            set_last_error(err.to_string());
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_empty() {
        let ptr = nexusq_version();
        assert!(!ptr.is_null());
        // SAFETY: `nexusq_version` returns a static, valid NUL-terminated string.
        let cstr = unsafe { CStr::from_ptr(ptr) };
        let version = cstr.to_str().unwrap();
        assert!(!version.is_empty());
        assert!(version.chars().next().unwrap().is_ascii_digit());
    }

    #[test]
    fn last_error_starts_null() {
        // A fresh thread has no error.
        std::thread::spawn(|| {
            let ptr = nexusq_last_error_message();
            assert!(ptr.is_null());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn string_free_accepts_null() {
        // SAFETY: Null is explicitly accepted by the function contract.
        unsafe {
            nexusq_string_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn cstr_to_str_handles_valid_input() {
        let s = CString::new("hola").unwrap();
        // SAFETY: `CString` owns a live NUL-terminated allocation for this call.
        let parsed = unsafe { cstr_to_str(s.as_ptr()) };
        assert_eq!(parsed, Some("hola"));
    }

    #[test]
    fn cstr_to_str_handles_null() {
        // SAFETY: Null is explicitly accepted by `cstr_to_str`.
        assert_eq!(unsafe { cstr_to_str(std::ptr::null()) }, None);
    }

    #[test]
    fn cstr_to_str_rejects_invalid_utf8() {
        let bytes = [0xffu8, 0x00];
        // SAFETY: `bytes` is a live NUL-terminated allocation; invalid UTF-8 is
        // rejected after the bounded C-string read.
        assert_eq!(unsafe { cstr_to_str(bytes.as_ptr().cast()) }, None);
    }

    #[test]
    fn null_vault_create_is_rejected_without_panicking() {
        // SAFETY: The exported API explicitly permits null pointers to be rejected.
        let rc =
            unsafe { nexusq_vault_create(std::ptr::null(), std::ptr::null(), std::ptr::null()) };
        assert_eq!(rc, -1);
        assert!(!nexusq_last_error_message().is_null());
    }

    #[test]
    fn successful_call_clears_previous_error() {
        // SAFETY: The exported API explicitly permits null pointers to be rejected.
        let _ =
            unsafe { nexusq_vault_create(std::ptr::null(), std::ptr::null(), std::ptr::null()) };
        assert!(!nexusq_last_error_message().is_null());
        assert!(!nexusq_version().is_null());
        assert!(nexusq_last_error_message().is_null());
    }
}

#[cfg(test)]
mod backend_metadata_tests {
    use super::{nexusq_backend_is_experimental, nexusq_backend_name};
    use std::ffi::CStr;

    #[test]
    fn c_abi_reports_compiled_provider() {
        // SAFETY: `nexusq_backend_name` returns a static, valid NUL-terminated string.
        let name = unsafe { CStr::from_ptr(nexusq_backend_name()) }
            .to_str()
            .unwrap();
        #[cfg(any(feature = "native-backend", feature = "native-backend-portable"))]
        assert_eq!(
            (name, nexusq_backend_is_experimental()),
            ("native-experimental", 1)
        );
        #[cfg(not(any(feature = "native-backend", feature = "native-backend-portable")))]
        assert_eq!((name, nexusq_backend_is_experimental()), ("rustcrypto", 0));
    }
}

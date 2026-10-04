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

/// Returns the library version as a static NUL-terminated string.
///
/// The returned pointer is owned by the library and must not be
/// freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn nexusq_version() -> *const c_char {
    clear_last_error();
    // A static CStr built once at compile time.
    const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr().cast()
}

/// Frees a string previously returned by a NEXUS-Q function.
///
/// Passing a null pointer is a no-op. Passing a pointer not returned
/// by this library is undefined behavior.
///
/// # Safety
///
/// `s` must be a pointer previously returned by one of the functions
/// in this crate, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nexusq_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // Reconstruct the CString and drop it.
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

/// Returns the last error message on the calling thread, or null.
///
/// The returned pointer is owned by the library and remains valid
/// until the next NEXUS-Q call on the same thread.
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
// `s` must be either null or a valid NUL-terminated C string.
unsafe fn cstr_to_str<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(s) }.to_str().ok()
}

// =============================================================================
// Vault
// =============================================================================

/// Creates a new vault at `path` with the given `password`.
///
/// Both strings must be NUL-terminated and valid UTF-8. `label` may
/// be null to create a vault without a label.
///
/// Returns 0 on success and a negative code on failure. On failure,
/// call `nexusq_last_error_message` to retrieve the reason.
///
/// # Safety
///
/// `path` and `password` must be valid NUL-terminated C strings.
/// `label` must be null or a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nexusq_vault_create(
    path: *const c_char,
    password: *const c_char,
    label: *const c_char,
) -> i32 {
    clear_last_error();
    let Some(path) = (unsafe { cstr_to_str(path) }) else {
        set_last_error("path is null or not valid UTF-8".into());
        return -1;
    };
    let Some(password) = (unsafe { cstr_to_str(password) }) else {
        set_last_error("password is null or not valid UTF-8".into());
        return -1;
    };
    let label = if label.is_null() {
        None
    } else {
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
/// code on failure.
///
/// # Safety
///
/// `path` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nexusq_vault_format_version(path: *const c_char) -> i32 {
    clear_last_error();
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
        unsafe {
            nexusq_string_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn cstr_to_str_handles_valid_input() {
        let s = CString::new("hola").unwrap();
        let parsed = unsafe { cstr_to_str(s.as_ptr()) };
        assert_eq!(parsed, Some("hola"));
    }

    #[test]
    fn cstr_to_str_handles_null() {
        assert_eq!(unsafe { cstr_to_str(std::ptr::null()) }, None);
    }

    #[test]
    fn cstr_to_str_rejects_invalid_utf8() {
        let bytes = [0xffu8, 0x00];
        assert_eq!(unsafe { cstr_to_str(bytes.as_ptr().cast()) }, None);
    }

    #[test]
    fn null_vault_create_is_rejected_without_panicking() {
        let rc =
            unsafe { nexusq_vault_create(std::ptr::null(), std::ptr::null(), std::ptr::null()) };
        assert_eq!(rc, -1);
        assert!(!nexusq_last_error_message().is_null());
    }

    #[test]
    fn successful_call_clears_previous_error() {
        let _ =
            unsafe { nexusq_vault_create(std::ptr::null(), std::ptr::null(), std::ptr::null()) };
        assert!(!nexusq_last_error_message().is_null());
        assert!(!nexusq_version().is_null());
        assert!(nexusq_last_error_message().is_null());
    }
}

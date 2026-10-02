// nexusq.hpp -- C++ wrapper around the NEXUS-Q C SDK.
//
// This is a header-only wrapper. Include it and link against the C
// library (libnexusq). It adds RAII, exceptions and std::string on
// top of the plain C API; it does not reimplement anything.
//
// Build (with the C library already built):
//
//     c++ -std=c++17 -I crates/nexusq-c/include \
//         -I crates/nexusq-cpp/include \
//         your_file.cpp \
//         -L target/debug -lnexusq \
//         -o your_program
//
// Run:
//
//     LD_LIBRARY_PATH=target/debug ./your_program

#ifndef NEXUSQ_HPP
#define NEXUSQ_HPP

#include <stdexcept>
#include <string>
#include <string_view>

extern "C" {
#include "nexusq.h"
}

namespace nexusq {

/// Exception thrown when a NEXUS-Q operation fails.
///
/// Carries the same message the C SDK would have put in
/// `nexusq_last_error_message` at the moment of the failure.
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message)
        : std::runtime_error(message) {}
};

namespace detail {

/// Fetches the last error message from the C SDK and throws it.
[[noreturn]] inline void throw_last_error() {
    const char* msg = nexusq_last_error_message();
    if (msg == nullptr) {
        throw Error("unknown NEXUS-Q error");
    }
    throw Error(std::string(msg));
}

} // namespace detail

/// Returns the library version.
inline std::string version() {
    const char* v = nexusq_version();
    return v ? std::string(v) : std::string{};
}

/// A vault file on disk.
///
/// This is a thin handle: it stores the path and the format version.
/// Operations that need to decrypt the vault are exposed by a future
/// Session type; opening without unlocking is all this class
/// supports today.
class Vault {
public:
    /// Creates a new vault at `path` with `password` and an optional
    /// `label`.
    ///
    /// # Exceptions
    ///
    /// Throws `nexusq::Error` if the vault cannot be created.
    static Vault create(std::string_view path,
                        std::string_view password,
                        std::string_view label = {}) {
        std::string path_str(path);
        std::string password_str(password);
        std::string label_str(label);

        const char* label_cstr = label.empty() ? nullptr : label_str.c_str();
        int rc = nexusq_vault_create(path_str.c_str(),
                                     password_str.c_str(),
                                     label_cstr);
        if (rc != 0) {
            detail::throw_last_error();
        }

        int version = nexusq_vault_format_version(path_str.c_str());
        if (version < 0) {
            detail::throw_last_error();
        }

        return Vault(std::move(path_str), version);
    }

    /// Returns the path of the vault file.
    [[nodiscard]] const std::string& path() const noexcept {
        return path_;
    }

    /// Returns the format version of the vault file.
    [[nodiscard]] int format_version() const noexcept {
        return format_version_;
    }

private:
    Vault(std::string path, int version)
        : path_(std::move(path)), format_version_(version) {}

    std::string path_;
    int format_version_;
};

} // namespace nexusq

#endif // NEXUSQ_HPP

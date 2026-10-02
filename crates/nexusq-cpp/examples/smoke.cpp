// Smoke test for the C++ wrapper.
//
// Build:
//   c++ -std=c++17 \
//       -I crates/nexusq-c/include \
//       -I crates/nexusq-cpp/include \
//       crates/nexusq-cpp/examples/smoke.cpp \
//       -L target/debug -lnexusq \
//       -o smoke
//
// Run:
//   LD_LIBRARY_PATH=target/debug ./smoke
//
// The smoke test creates a vault, prints its version and removes it
// again.

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include <nexusq.hpp>

int main() {
    std::cout << "nexusq version: " << nexusq::version() << "\n";

    const char* home = std::getenv("HOME");
    if (home == nullptr) {
        std::cerr << "HOME is not set\n";
        return 1;
    }

    std::string path = std::string(home) + "/nexusq_cpp_smoke.nqv";
    std::remove(path.c_str());

    try {
        nexusq::Vault vault = nexusq::Vault::create(path, "smoke-test", "cpp-smoke");
        std::cout << "vault created at " << vault.path() << "\n";
        std::cout << "vault format version: " << vault.format_version() << "\n";
    } catch (const nexusq::Error& e) {
        std::cerr << "error: " << e.what() << "\n";
        std::remove(path.c_str());
        return 1;
    }

    std::remove(path.c_str());
    std::cout << "cleaned up\n";
    return 0;
}

# NEXUS-Q C++ SDK

Header-only C++ wrapper around the [C SDK](../nexusq-c). It adds
RAII, exceptions and `std::string` on top of the plain C API. It does
not reimplement anything: every call goes through `libnexusq`.

## Requirements

- A C++17 compiler (clang or gcc).
- The C SDK built (`cargo build -p nexusq-c`).

## Usage

Copy `include/nexusq.hpp` into your project, or add it to your
include path. Then compile with the C SDK's include directory and
link against `libnexusq`:

```bash
c++ -std=c++17 \
    -I path/to/nexusq/crates/nexusq-c/include \
    -I path/to/nexusq/crates/nexusq-cpp/include \
    your_file.cpp \
    -L path/to/nexusq/target/debug -lnexusq \
    -o your_program
```

Run with the library in the load path:

```bash
LD_LIBRARY_PATH=path/to/nexusq/target/debug ./your_program
```

Example

```cpp
#include <iostream>
#include <nexusq.hpp>

int main() {
    std::cout << "nexusq version: " << nexusq::version() << "\n";

    try {
        nexusq::Vault vault =
            nexusq::Vault::create("my.nqv", "password", "my-label");
        std::cout << "format version: "
                  << vault.format_version() << "\n";
    } catch (const nexusq::Error& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
```

What is available

The wrapper currently exposes:

· nexusq::version() — returns the library version as a
  std::string.
· nexusq::Error — exception type thrown by every operation that
  fails. Carries the same message the C SDK would have returned.
· nexusq::Vault — creates and inspects a vault file:
  · Vault::create(path, password, label = "")
  · vault.path()
  · vault.format_version()

More operations (sessions, keys, signatures) land as the C SDK grows.

Testing

A smoke test lives at examples/smoke.cpp. Build and run it with:

```bash
c++ -std=c++17 \
    -I crates/nexusq-c/include \
    -I crates/nexusq-cpp/include \
    crates/nexusq-cpp/examples/smoke.cpp \
    -L target/debug -lnexusq \
    -o smoke
LD_LIBRARY_PATH=target/debug ./smoke
```

Expected output:

```
nexusq version: 0.1.0
vault created at /home/you/nexusq_cpp_smoke.nqv
vault format version: 1
cleaned up
```


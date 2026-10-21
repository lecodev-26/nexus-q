# NEXUS-Q Ruby SDK

Ruby bindings for NEXUS-Q. A thin wrapper over the [C SDK](../../crates/nexusq-c)
using the `ffi` gem. It does not reimplement anything: every call goes
through `libnexusq`.

## Requirements

- Ruby 3.0 or newer.
- The `ffi` gem (`gem install ffi`).
- Published releases automatically download the version-matched runtime and
  verify its SHA-256 checksum on Linux x64/ARM64 glibc, macOS ARM64, and Windows
  x64. Rust is not required by SDK consumers; the library is cached under
  `~/.cache/nexusq/<version>/<runtime-asset>`.
- `NEXUSQ_LIBRARY` remains an advanced override for a local/custom library.

## Usage

```ruby
require "ffi"
require_relative "bindings/ruby/nexusq"

puts "nexusq version: #{Nexusq.version}"

vault = Nexusq::Vault.create("my.nqv", "password", "my-label")
puts "vault created at #{vault.path}"
puts "format version: #{vault.format_version}"
```

Run normally after installing the published SDK:

```bash
ruby your_program.rb
```

For source-checkout smoke tests or a custom build, set `NEXUSQ_LIBRARY` to the library path.

## What is available

- `Nexusq.version` — returns the library version.
- `Nexusq.last_error` — returns the last C SDK error message.
- `Nexusq::Vault`:
  - `Nexusq::Vault.create(path, password, label)` — creates a new vault.
  - `vault.path` — returns the vault file path.
  - `vault.format_version` — returns the format version.

More operations land as the C SDK grows.

## Testing

The smoke test lives at `examples/smoke/smoke.rb`. From the repository root:

```bash
NEXUSQ_LIBRARY=target/debug/libnexusq.so \\
ruby bindings/ruby/examples/smoke/smoke.rb
```

Expected output:

```
nexusq version: 0.1.0
vault created at /tmp/nexusq_ruby_smoke_1234.nqv
vault format version: 1
smoke test passed
```

The Ruby binding is intentionally a thin wrapper over the C SDK, matching
the Go SDK architecture. No cryptography or business logic is duplicated
in Ruby.

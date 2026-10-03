# NEXUS-Q Ruby SDK

Ruby bindings for NEXUS-Q. A thin wrapper over the [C SDK](../../crates/nexusq-c)
using the `ffi` gem. It does not reimplement anything: every call goes
through `libnexusq`.

## Requirements

- Ruby 3.0 or newer.
- The `ffi` gem (`gem install ffi`).
- The C SDK built (`cargo build -p nexusq-c`).
- `libnexusq.so` available at runtime through `LD_LIBRARY_PATH` or
  `NEXUSQ_LIBRARY`.

## Usage

```ruby
require "ffi"
require_relative "bindings/ruby/nexusq"

puts "nexusq version: #{Nexusq.version}"

vault = Nexusq::Vault.create("my.nqv", "password", "my-label")
puts "vault created at #{vault.path}"
puts "format version: #{vault.format_version}"
```

Run with:

```bash
NEXUSQ_LIBRARY=/path/to/nexusq/target/debug/libnexusq.so ruby your_program.rb
```

If the library directory is already on the dynamic loader path:

```bash
LD_LIBRARY_PATH=/path/to/nexusq/target/debug ruby your_program.rb
```

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

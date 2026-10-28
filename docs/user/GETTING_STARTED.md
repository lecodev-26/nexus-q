# Getting Started

## Requirements

- Rust 1.88 or newer (the v4.1.2 workspace declares `rust-version = "1.88"`; the exact-commit MSRV CI passed).
- Git.
- Linux/Android Termux is the currently exercised development environment.
- A supported target toolchain for other platforms.

## Build

From the repository root:

```bash
cargo build --workspace
```

For optimized release binaries:

```bash
cargo build --workspace --release
```

The main binaries are `target/debug/nexusq` and `target/debug/nexusq-server`.

## First local workflow

Create a vault:

```bash
./target/debug/nexusq vault create ./example.nqv
```

The CLI prompts for the vault password without echoing it.

Check the vault without unlocking it:

```bash
./target/debug/nexusq vault status ./example.nqv
```

Run local health and diagnostics:

```bash
./target/debug/nexusq health
./target/debug/nexusq diagnostics --vault ./example.nqv
```

For scripted use, prefer `--password-file` over putting a password on the command line.

## First key

Generate a signing key:

```bash
./target/debug/nexusq key generate ./example.nqv --algorithm ed25519 --purpose sign --password-file ./password.txt
```

Treat `password.txt` as a secret: restrict its permissions and never commit it.

For the complete command surface see [CLI Guide](CLI.md).

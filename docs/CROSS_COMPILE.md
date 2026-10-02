# Cross-compiling NEXUS-Q

This document records how to build NEXUS-Q for targets other than the
host, using the setup we validated in Termux on 2026-09-27. It is a
practical recipe; the rationale for portability lives in
`docs/ARCHITECTURE.md` §2.3.

## Verified combinations

| Host                    | Target                          | Status      |
|-------------------------|---------------------------------|-------------|
| aarch64-linux-android   | aarch64-linux-android (native)  | Verified |
| aarch64-linux-android   | riscv64gc-unknown-linux-gnu     | Verified (2026-09-27) |
| x86_64-linux-gnu        | x86_64-linux-gnu (native)       | Untested but trivial |

The RISC-V cross-compile is significant because it exercises the whole
dependency tree against an architecture that shares nothing with ARM:
endianness assumptions, pointer width and atomic width all differ
from the host.

## Why this works

NEXUS-Q is pure Rust on the cryptographic path. It does not link
OpenSSL, libsodium, or any C library beyond what the Rust standard
library already pulls in (`libc` on Unix targets). This is what makes
cross-compiling to a new architecture a matter of adding a target and
re-running Cargo.

Bindings to C would have required a cross-compiled C toolchain per
target, a cross-compiled sysroot, and per-target adjustments to the
build scripts of every crate involved. We avoided that on purpose; see
ADR 0001.

## Recipe: RISC-V on Android/Termux

Termux does not ship `rustup`, and the `rust-std-riscv64-*` packages
are not in the Termux repository. We therefore install Rust inside a
Debian container running under `proot-distro`.

### One-time setup

```bash
# Install proot-distro and a Debian container.
pkg install proot-distro
proot-distro install debian

# Enter Debian.
proot-distro login debian

# Inside Debian:
apt update
apt install -y curl ca-certificates

# Install rustup inside Debian.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
sh /tmp/rustup-init.sh -y --default-toolchain stable --profile minimal

# Make rustup available in this shell.
export PATH=/root/.cargo/bin:$PATH

# Add the RISC-V target.
rustup target add riscv64gc-unknown-linux-gnu

# Exit Debian.
exit
```

Rust, its toolchain and the RISC-V standard library are now inside the
Debian container, not on the Android host. They do not interfere with
Termux's own Rust installation.

Building

From Termux, invoke cargo inside the container. The container sees
the Termux home directory at
/data/data/com.termux/files/home, so the repository is reachable
without mounting anything:

```bash
proot-distro login debian -- bash -c "
  export PATH=/root/.cargo/bin:\$PATH
  cd /data/data/com.termux/files/home/projects/nexusq
  cargo build --target riscv64gc-unknown-linux-gnu -p nexusq-core
"
```

The first build takes around a minute: it compiles every dependency
for the new target. Subsequent builds are incremental and fast.

Verifying the artifacts

```bash
proot-distro login debian -- bash -c "
  cd /data/data/com.termux/files/home/projects/nexusq
  file target/riscv64gc-unknown-linux-gnu/debug/deps/*.o
"
```

A successful build reports:

```text
ELF 64-bit LSB relocatable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV)
```

Recipe: RISC-V on a Linux host with rustup

If the host already has rustup:

```bash
rustup target add riscv64gc-unknown-linux-gnu
cargo build --target riscv64gc-unknown-linux-gnu -p nexusq-core
```

Same artifact, no container. The container path is only necessary
because Termux cannot run rustup directly.

Running the RISC-V binary

Building is one step; executing is another. Running the resulting
binary requires either:

· Real RISC-V hardware, or
· An emulator. qemu-user-riscv64 from the Termux repository can
  execute individual RISC-V Linux binaries without emulating an
  entire system.

Running NEXUS-Q end to end under qemu-user is not part of v1.0
verification. The build itself is the milestone: it proves the code is
free of host assumptions that would prevent deployment on a RISC-V
device.

Caveats

· No C toolchain is needed for NEXUS-Q itself. If a future
  dependency requires one, the container setup will need
  gcc-riscv64-linux-gnu as well.
· getrandom works on RISC-V Linux through the standard
  getrandom(2) syscall. No changes are required.
· Endianness. RISC-V in the Linux profile is little-endian, like
  ARM and x86_64. If a big-endian RISC-V target becomes relevant, the
  serialization layer (ciborium) handles endianness portably, but
  the KATs in crypto/hash.rs and crypto/kdf.rs should be rerun
  against the target.
· Atomic width. RISC-V has 32-bit and 64-bit atomics depending on
  the extension set. The riscv64gc target enables A (atomics), so
  Arc, AtomicBool and similar types behave as expected.

Reference

· docs/ARCHITECTURE.md §2.3 — hardware-agnostic design principle
· ADR 0001 — why NEXUS-Q uses pure-Rust cryptography
· Rust platform support: 
  EOF
  wc -l docs/CROSS_COMPILE.md && head -20 docs/CROSS_COMPILE.md

# Unsafe Rust policy and inventory

## Policy

NEXUS-Q keeps unsafe Rust out of ordinary application and cryptographic logic. Every project-owned Rust `unsafe` block, unsafe function, unsafe implementation, and unsafe extern block must have a nearby `// SAFETY:` comment within the preceding five source lines. The comment must state the actual invariant relied upon at that site (for example pointer validity and lifetime, ABI agreement, allocation ownership, or runtime CPU-feature detection); generic statements such as “this is safe” are not sufficient.

Public unsafe functions must also document their caller obligations in a `# Safety` section. New unsafe code requires a narrow boundary, a documented reason, and review of the invariant at both declaration and call sites. Do not add unsafe code to `nexusq-core` without an explicit, documented exception. The core crate denies unsafe code by default; the Windows atomic-replacement function is the sole narrowly scoped allowance and is covered by the same source policy.

The repository-wide source gate is `.github/scripts/check-unsafe-policy.py`. It scans repository-owned Rust sources and excludes third-party `vendor/` trees and generated/build directories; it fails when an unsafe site lacks a nearby justification. It runs in NEXUS-Q Fast CI on every pull request and push to `main`. The check is intentionally a source-policy guard, not a Rust parser or proof of soundness; code review must still verify that each explanation is true and complete.

## Current project-owned unsafe boundaries

| Source | Purpose and invariant |
| --- | --- |
| `crates/nexusq-c/src/lib.rs` | C ABI boundary. Raw C strings and ownership transfer are constrained by documented pointer, NUL-termination, lifetime, and allocator contracts. The crate contains no cryptographic implementation. |
| `crates/nexusq-kernels/src/x86_64/avx2.rs` | AVX2 SIMD kernels. Callers perform runtime feature detection; loads/stores are bounded to fixed-size polynomial/state buffers and arithmetic ranges are documented at the intrinsic sites. |
| `crates/nexusq-native-backend/src/lib.rs` | Experimental native backend FFI. Rust declarations match pinned upstream C headers; buffers have algorithm-defined sizes; the RNG callback requires a writable output range. This backend remains opt-in, experimental, and unaudited. |
| `crates/nexusq-core/src/storage/atomic.rs` | Windows `MoveFileExW` atomic replacement. This is the sole explicitly allowed unsafe exception in the otherwise deny-by-default core crate; UTF-16 buffers are owned, NUL-terminated, and live across the call. |
| `crates/nexusq-ha/src/lib.rs` and `crates/nexusq-admin/src/lib.rs` | Windows `MoveFileExW` atomic replacement for HA/admin storage. UTF-16 buffers are owned, NUL-terminated, and live across the call; the declaration mirrors the Windows system ABI. |
| `arena/runners/nexusq/src/main.rs` and `arena/runners/nexusq-native/src/main.rs` | Architecture-specific performance-counter reads. The instruction sequences and output registers are documented at each call site. |
| `arena/runners/nexusq/src/bin/profile_hotspots.rs` | Benchmark-only counting allocator. Every operation forwards the original pointer/layout arguments unchanged to `std::alloc::System`; counters are independent atomics. |

The Dylint crypto rules remain focused on semantic review candidates such as secret comparisons, panic-based error handling, and nonce literals. Dylint is not used for the `SAFETY` comment requirement because the requirement is about source-comment placement and explicit repository boundaries; the dedicated source gate is simpler and runs in the fast CI path. Neither tool proves memory safety.

## Unsafe dependency inventory

The `NEXUS-Q Supply Chain Inventory` workflow pins `cargo-geiger` to 0.14.0 and uploads a machine-readable JSON artifact named `cargo-geiger-<commit-sha>`. It scans each package in the root workspace plus the separately locked `crates/nexusq-native-backend`, `arena/runners/nexusq`, and `arena/runners/nexusq-native` workspaces. The workflow refreshes on Rust source, manifest, lockfile, and supply-chain policy changes; artifacts are retained for 30 days.

`cargo-geiger` reports unsafe usage in the dependency graph. It is an inventory and triage aid, not a security certification, a proof of safety, or a substitute for reviewing project-owned unsafe blocks and third-party code. Root-workspace, native-backend, and Arena reports share the same artifact so reviewers can distinguish the separately managed dependency boundaries.

## Exceptions and review

The current core exception is `crates/nexusq-core/src/storage/atomic.rs::replace_file`. It preserves Windows atomic-replacement semantics through `MoveFileExW`, which is an unsafe platform API; the wrapper owns both NUL-terminated UTF-16 buffers for the full call. Owner: NEXUS-Q project maintainer. Recorded: 2026-11-15. Re-review before the next stable release and whenever the Windows ABI, flags, or buffer construction changes.

Any additional exception must identify the exact file/function, why safe Rust or an existing safe abstraction cannot be used, the invariant being relied upon, the reviewer/owner, and the date for reconsideration. A new exception must update this inventory and the relevant threat model. A source-gate pass only confirms that a nearby comment exists; it does not validate the comment's truth.

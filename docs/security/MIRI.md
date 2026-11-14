# Miri memory-safety checks

NEXUS-Q runs a focused Miri job for the Rust implementation of its C ABI. The
job runs `cargo miri test -p nexusq-c --locked` with the pinned
`nightly-2026-11-01` toolchain. It is triggered by relevant pull requests, runs
weekly on Monday, and can be started manually. The scheduled run uploads its
console output as a 30-day GitHub Actions artifact; the workflow run remains
the authoritative pass/fail result.

## Covered surface

The `nexusq-c` unit tests exercise Rust-side pointer and string handling,
including:

- conversion of valid NUL-terminated UTF-8 strings;
- rejection of null and invalid-UTF-8 inputs;
- rejection of null vault arguments without entering vault or cryptographic
  operations;
- static C string return values and provider metadata;
- null handling in the string-free API; and
- thread-local last-error behavior.

The crate is tested with its default features. The experimental native backend
is not enabled by this job.

## Exclusions and interpretation

Miri only executes the selected Rust test paths. It does not validate arbitrary
pointers supplied by an external C caller: every non-null pointer passed to a
C ABI function must still satisfy that function's documented validity,
readability, termination, ownership, and lifetime preconditions. Passing a
dangling, unreadable, unterminated, interior, already-freed, or foreign pointer
where prohibited remains undefined behavior.

The following surfaces are not claimed as Miri-covered:

- `nexusq-native-backend` is a separate Cargo workspace and links native C,
  architecture-specific assembly, and foreign functions that Miri cannot
  interpret as Rust code.
- The AVX2 implementation in `nexusq-kernels` uses hardware intrinsics and
  inline assembly. Miri is not a substitute for native execution, differential
  testing, or hardware-specific validation of those routines.
- Windows-only system FFI paths are not exercised by the Linux Miri runner.
- The job does not establish cryptographic correctness, constant-time behavior,
  safety of third-party native libraries, or absence of all undefined behavior.

If a Miri failure occurs, preserve the failing test and diagnostic, identify
whether it is project code or an unsupported dependency/platform operation,
and either fix the defect or record a narrowly scoped, reviewed exclusion.
Do not silence a failure by broadly disabling Miri checks.

## Reproduction

From a clean checkout with the pinned nightly installed:

```sh
rustup toolchain install nightly-2026-11-01 --component miri --profile minimal
cargo +nightly-2026-11-01 miri setup
cargo +nightly-2026-11-01 miri test -p nexusq-c --locked
```

Miri is an interpreter-based dynamic check over executed paths, not a proof of
memory safety. Keep the normal Fast CI and dedicated native/FFI review gates in
place.

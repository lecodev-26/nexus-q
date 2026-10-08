# Contributing to NEXUS-Q

Thanks for contributing. NEXUS-Q is security-sensitive software, so correctness,
reviewability, interoperability and evidence take priority over speed or code
volume.

## Before opening a change

1. Read `docs/THREAT_MODEL.md`, `docs/SECURITY_MODEL.md` and the relevant
   cryptography/storage documentation.
2. Keep changes scoped to one issue or clearly related concern.
3. Do not change cryptographic parameters, wire formats, or security semantics
   merely to improve a benchmark.
4. Do not add custom cryptography when a maintained primitive is available.
5. Never commit credentials, private keys, vaults, fuzz crashes, or generated
   secret material.

## Development checks

Run the narrowest useful checks locally, for example:

```text
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Security-sensitive changes should also consider the repository's audit, deny,
fuzz, interoperability and secret-scanning workflows.

## Pull requests

PRs should explain:

- what changed and why;
- security/correctness impact;
- tests and evidence run;
- performance evidence if performance is the objective;
- compatibility or migration impact;
- any known limitation or deferred work.

For cryptographic changes, explicitly state whether parameters, algorithms,
serialization, constant-time assumptions, zeroization, or key lifetimes changed.

## Review standard

A benchmark win is not sufficient evidence to retain a crypto optimization.
Security, correctness and interoperability outrank performance. New backend
providers require a documented boundary, scalar fallback, reproducibility,
security review and comparative evidence.

## Licensing

By contributing, contributors must ensure they have the right to submit the
work under the repository's applicable MIT OR Apache-2.0 licensing terms. Keep
third-party code provenance and license notices intact.

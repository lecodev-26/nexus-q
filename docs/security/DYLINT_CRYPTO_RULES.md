# Dylint cryptographic rules

NEXUS-Q maintains a small Dylint library in `tools/dylint/nexusq-crypto-lints`.
It runs in its own GitHub Actions workflow with a pinned nightly toolchain; it
is deliberately separate from Fast CI and does not change the workspace MSRV.

The separate repository-wide `// SAFETY:` comment requirement is enforced by `.github/scripts/check-unsafe-policy.py` in Fast CI, not by Dylint; see [Unsafe Rust policy and inventory](UNSAFE_CODE_POLICY.md). Dylint remains focused on semantic cryptographic review candidates.

## Rules

- `NEXUSQ_CRYPTO_SECRET_COMPARISON` flags ordinary `==`/`!=` expressions and
  `.eq()`/`.ne()` method calls whose source text contains identifiers commonly
  used for secret-bearing values (including `secret`, `private_key`, `mac`,
  `token`, `tag`, `seed`, `password`, `dk_pke`, and the ML-KEM `.z` field).
  Review the finding and use a constant-time primitive such as
  `subtle::ConstantTimeEq` or `CtEq` when the compared value is secret-dependent.
- `NEXUSQ_CRYPTO_UNWRAP_EXPECT` flags `.unwrap()` and `.expect()` calls in
  source files whose path is under a `crypto` directory. Prefer error
  propagation or explicit error mapping in cryptographic operations.
- `NEXUSQ_CRYPTO_NONCE_LITERAL_REUSE` is a narrow heuristic for repeated
  explicit byte-string nonce literals on encryption-call lines in one function.
  It does not perform data-flow analysis and cannot detect reuse through
  variables, aliases, loops, helper functions, or separate functions.

## False positives and limitations

These are review-oriented warnings, not vulnerability proofs. Identifier-name
matching can miss secrets with unfamiliar names, aliases, helper functions, or
secret-dependent branches that do not use equality operators; it can also flag
public identifiers.
The panic lint is path-based and does not infer whether a call is reachable in
production or test-only code. The nonce rule intentionally detects only a
small literal pattern; a clean run is not evidence that nonce reuse is absent.
All findings require human review. Do not silence a finding globally: add a
narrow, explained exception at the call site when a reviewed invariant justifies
it.

## Running locally

Install the pinned nightly with `rustc-dev`, `rust-src`, and
`llvm-tools-preview`, then install `cargo-dylint` and `dylint-link` 6.4.0 and
run:

```sh
cargo +nightly-2026-11-01 dylint --path tools/dylint/nexusq-crypto-lints -- --workspace --all-targets
```

The CI workflow is the validation authority for pull requests. This analysis
is supplemental and does not replace Fast CI, CodeQL, cryptographic review, or
runtime testing.

Positive and negative source fixtures are kept in
`tools/dylint/nexusq-crypto-lints/fixtures/`; the library unit tests exercise
the corresponding match/no-match cases. They are deliberately small and do not
claim full Rust data-flow analysis.

The reviewed authentication and key-comparison surfaces are inventoried in
[Constant-time comparison inventory](CONSTANT_TIME_COMPARISONS.md). Functional
tests do not prove constant-time behavior.

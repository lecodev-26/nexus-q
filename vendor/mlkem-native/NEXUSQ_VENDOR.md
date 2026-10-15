# Vendored mlkem-native

- Upstream: https://github.com/pq-code-package/mlkem-native
- Tag: v2.0.0
- Commit: `d1b2fe782888bdb761a50336012923180be7f502`
- Imported paths: `mlkem/` and `LICENSE` only, unmodified (`git archive d1b2fe782888bdb761a50336012923180be7f502 mlkem LICENSE`).
- Why this commit: it is exactly the commit imported by AWS-LC
  `ec05f25ef5bcb1bf03d2e2f44ba57973a878e0ba` (the Arena comparator), see
  https://github.com/aws/aws-lc/blob/ec05f25ef5bcb1bf03d2e2f44ba57973a878e0ba/crypto/fipsmodule/ml_kem/META.yml
- License: Apache-2.0 OR ISC OR MIT (see `LICENSE`).
- Integrity: the `native-backend-gate` workflow re-fetches upstream at this
  commit and fails on any difference (`diff -r`), then runs the upstream
  functional, KAT and NIST ACVP test suites at the same commit.
- NEXUS-Q never edits files under this directory. All configuration lives in
  `crates/nexusq-native-backend/csrc/`.

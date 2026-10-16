# Vendored mldsa-native

- Upstream: https://github.com/pq-code-package/mldsa-native
- Tag: v2.0.0
- Commit: `834a90d5e846ffa1e1611bd24e160bb2e9b86d35`
- Imported paths: `mldsa/` and `LICENSE` only, unmodified (`git archive 834a90d5e846ffa1e1611bd24e160bb2e9b86d35 mldsa LICENSE`).
- Why this commit: it is exactly the commit imported by AWS-LC
  `ec05f25ef5bcb1bf03d2e2f44ba57973a878e0ba` (the Arena comparator), see
  https://github.com/aws/aws-lc/blob/ec05f25ef5bcb1bf03d2e2f44ba57973a878e0ba/crypto/fipsmodule/ml_dsa/META.yml
- License: Apache-2.0 OR ISC OR MIT (see `LICENSE`).
- Integrity: the `native-backend-gate` workflow re-fetches upstream at this
  commit and fails on any difference (`diff -r`), then runs the upstream
  functional, KAT and NIST ACVP test suites at the same commit.
- NEXUS-Q never edits files under this directory. All configuration lives in
  `crates/nexusq-native-backend/csrc/`.

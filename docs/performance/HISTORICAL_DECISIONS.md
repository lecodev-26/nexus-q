# Historical Decisions and Migration Record

This new performance initiative is tracked by [Issue #48](https://github.com/lecodev-26/nexus-q/issues/48). The previous V4 implementation line is preserved for reference in [PR #46](https://github.com/lecodev-26/nexus-q/pull/46), [PR #47](https://github.com/lecodev-26/nexus-q/pull/47), and [Issue #23](https://github.com/lecodev-26/nexus-q/issues/23).

## New-line baseline
The dedicated branch `perf/issue-48-native-assembly-gate` was created from `nexusqv4` at base commit `dc560e0817d8d3a39b69f0c7811bcaab57b23cda`. The selected baseline is intentionally separate from the 153-commit PR #46 branch; reusable components are imported selectively and recorded in `FILE_MIGRATION_MATRIX.md`.

## Why the plan was reset
The previous line established useful scalar kernels, experimental AVX2 paths, vendored RustCrypto integration, benchmark sampling and CI evidence, but the recorded production performance gate remained red. The new line makes native assembly an explicit implementation requirement from the first new optimized kernel and isolates a dedicated performance-focused CI.

## Historical documents retained
- `history/V3_V4_ROADMAP.md`
- `history/V4_ISSUE_23_EXECUTION.md`
- `history/V4_PHASE0_MEASUREMENT_CONTRACT.md`
- `history/V4_ARENA_BASELINE_AUDIT.md`
- `history/V4_ISSUE_23_CODE_AUDIT_2026-10-15.md`
- `history/V4_ISSUE_23_COMPARATIVE_KERNEL_AUDIT_2026-10-15.md`
- `history/DOCUMENTATION_AUDIT_2026-10-12.md`
- `history/REPOSITORY_AUDIT_2026-10-10.md`

These documents preserve what was known at the time; they are not automatically authoritative for the current code. When a statement conflicts with the current repository or new CI evidence, record the conflict and update the active document without rewriting the historical record.

## Migration policy
- Do not merge PR #46 wholesale merely to reuse its documentation or kernels.
- Do not discard benchmark harness improvements, schemas, raw samples, manifests, or provenance records without review.
- Do not remove repository-wide security, fuzzing, SDK or release workflows to make the specialized CI shorter.
- Reused source retains its upstream license and attribution; imported code is re-reviewed before further optimization.
- Close the prior issue/PR only after the new line is usable and cross-links explain the transition.

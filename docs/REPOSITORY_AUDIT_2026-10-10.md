# NEXUS-Q repository audit — 2026-10-10

## Scope and method

This audit covers the checked-out repository, the five GitHub branch refs visible during the audit, local Git worktrees, all 18 GitHub Actions workflow YAML files, V4 benchmark/provenance workflows, the standalone Arena runner and AWS-LC adapter, the C ABI boundary, artifact manifests, and the PR #46 relationship to its base. It uses static inspection and lightweight validation; heavy builds/tests are delegated to GitHub Actions, not Termux.

## Findings fixed on the V4 PR branch

1. **PR merge conflict.** The base `nexusqv4` and PR head independently added `.github/workflows/v4-issue23-phase0.yml`, leaving PR #46 in GitHub's `DIRTY` state. The base branch has been merged into the PR branch and the enhanced head workflow retained as the conflict resolution.
2. **Status publisher failed open.** The V4 status-publishing script previously suppressed compare-API errors, which could leave an empty changed-file list and incorrectly publish green statuses. It now requires a valid `identical`/`ahead` comparison and a valid file list before publishing; API errors stop status publication.
3. **Dependency provenance was only recorded, not enforced.** Phase 0 now fails unless the locked Arena dependency trees prove `ml-kem` and `module-lattice` resolve from the repository's `vendor/` paths.
4. **NEXUS-Q operation coverage was not asserted.** The measurement workflow now requires all nine distinct ML-KEM-768/1024 and ML-DSA-65 operations, keeps cached and conventional ML-DSA verification separate, and verifies the expected record count.
5. **Matched-host CPU metadata was incomplete.** The AWS-LC adapter now records the CPU feature list supplied by the same CI host, the actual fixed run order, the full pinned AWS-LC commit, and the current distribution-statistics harness version. CI asserts CPU model/features and release profile match across the two implementations.
6. **Statistic conventions differed.** Rust and C now use the same even-count median convention and nearest-rank p95. Unit tests cover the Rust statistic definitions and run in the GitHub measurement workflow.
7. **C ABI helper exposed an unconstrained lifetime.** `nexusq-c`'s raw-pointer helper returned `&'a str` for a lifetime unrelated to the pointer. It now accepts an already validated `&CStr` and returns a borrow tied to that reference; pointer conversion stays at the documented unsafe FFI call sites, and the password is not copied into an extra unzeroized allocation.
8. **V4 PRs missed the full non-fuzz security CI.** `security-ci.yml` now also triggers for PRs targeting `nexusqv4`, running formatting, Clippy, workspace tests, dependency audit/deny, and secret scanning. Long fuzz/release soaks remain separately gated.
9. **Formatting and documentation drift.** Formatting in the standalone Arena crate was corrected, and the baseline audit document now describes the active push/status workflow rather than the superseded PR-only trigger design.

## Validation performed

- All 18 workflow YAML files parse successfully.
- `bash -n` passes for shell steps extracted from the Phase 0, measurement, and security workflows.
- `cargo fmt --all -- --check` passes.
- `cargo fmt --manifest-path arena/runners/nexusq/Cargo.toml -- --check` passes.
- `git diff --check` passes.
- The repository-level `artifact-archive/SHA256SUMS-2026-10-09.txt` manifest verifies.
- Run-local SHA-256 manifests verify for Phase 0 run `38070847418-1` and measurement run `38070847407-1`.
- The Phase 0 evidence shows the Arena runner resolves `ml-kem` from `vendor/ml-kem` and `module-lattice` from `vendor/module-lattice`.
- A heuristic scan found no tracked files matching common private-key/API-token patterns outside the vendor/archive trees. This is not a substitute for the Gitleaks CI scan.
- The two most recent Phase 0 and measurement workflows completed successfully and their named statuses appeared on the PR head. Those runs tested source SHA `70607e00c520a69456998c68bb8f214fee1cb6e3`; the later commits only archived their evidence.

## Remaining blockers — Phase 0 is not complete

- AWS-LC currently provides no ML-KEM-1024 comparator records; a valid best comparator for that operation is still needed.
- Measurement semantics/layers are not yet equivalent across all nine operations: ML-KEM-768 and ML-DSA use `nexusq-core` wrappers, while ML-KEM-1024 uses the raw `ml-kem` API.
- CPU frequency/governor are unavailable/unknown in the current hosted-runner records, and cycle counts (`rdtsc`/`cntvct` or a safe unsupported-platform fallback) are not implemented.
- The measurement workflow is a matched-host harness smoke test, not a per-operation performance regression gate. No accepted ratios or performance-leadership claim may be derived from it.
- A reviewed comparator/ratio gate and at least three reproducible final runs remain outstanding.
- `crates/nexusq-kernels` and all implementation, differential-correctness, constant-time, KAT, fuzz, sanitizer, architecture-matrix, and release-hygiene phases remain future work. A green Phase 0 check does not mean the kernels exist or that Issue #23 is done.

## Repository-level caveats (observed, not silently changed)

- At audit time, `main`, `nexusqv2`, and `nexusqv3` all pointed to `9cbabfb`; `nexusqv4` pointed to `dc560e0`. The V2/V3 refs are therefore aliases of the current `main` tip, not distinct branch tips. No branch refs were moved because this may be intentional and rewriting them would be disruptive.
- GitHub reported all five branch refs as unprotected. The CI statuses are visible, but branch protection/required checks are not enforced by a protection rule. This is repository policy rather than a code fix; enable it only after choosing a policy that does not lock out the sole maintainer or the archive-bot pushes.
- The Issue #23 body and execution tracker now agree that `nexusq-kernels` is the only crate allowed to implement unsafe SIMD/assembly/cryptographic kernels, while `nexusq-core` continues to forbid unsafe code and `nexusq-c` retains only its minimal, separately audited C ABI pointer-handling exception. The issue title still says “V3” while the active implementation PR is V4; this appears to be historical naming and was not renamed without a deliberate scope decision.
- A separate local detached V1-zeroize worktree contains uncommitted edits to `Cargo.toml` (enabling the `ml-dsa` zeroize feature) and `arena/runners/nexusq/Cargo.lock`. Those edits were preserved and were not folded into the V4 PR; review them separately before deciding whether to commit or discard them.

## Merge/release posture

PR #46 remains a draft and must stay unmerged while the Phase 0 blockers above remain open. The V4 branch is the only branch to receive the audit fixes. Do not push these fixes directly to `main` or `nexusqv4`; merge resolution and subsequent commits belong to the PR head, followed by GitHub Actions verification.

# Documentation audit — 2026-10-12

## Scope and method

Static review of first-party READMEs, changelog/security/contribution guidance, the version and V4 roadmaps, Issue #23 tracker and measurement contract, Arena protocol, user documentation entry points, deployment/observability/API reference docs, and dated audit reports. The review compared documentation statements with the checked-out source tree and workflow inventory. No build, test, benchmark, fuzz campaign, or CI-status polling was performed for this audit.

Third-party/vendor documentation and generated/historical artifact contents were not rewritten. Historical benchmark numbers and past audit observations were retained as historical evidence rather than silently edited.

## Findings and corrections

1. **V4 status drift:** the root README and version roadmap described V4 as merely planned, even though PR #46 is active and `crates/nexusq-kernels` exists. Updated the current status while explicitly saying optimized backends and acceptance evidence remain incomplete.
2. **Issue #23 tracker drift:** the tracker described the kernel crate as initial/partial work and said no push/CI had started from the working changes. Updated the source-level description to the current scalar operations and removed the obsolete pre-push statement. The tracker does not claim a current CI result.
3. **Arena protocol drift:** the protocol described mean-only results and suggested median/p95/stddev would be future work. Updated it to describe the current per-operation samples/statistics and V4 median/p95 gate, while distinguishing historical artifacts.
4. **Security workflow drift:** `SECURITY.md` described V2-only fuzz durations as current policy. Replaced that with the current workflow source of truth and explicitly documented that long fuzz soaks are not part of iterative `v4/**` runs.
5. **Dated audit reports looked live:** added dated correction notes to the V4 Arena baseline audit and 2026-10-10 repository audit so historical statements about a missing kernel crate or old workflow inventory are not mistaken for current state.
6. **Release/changelog context:** added an Unreleased V4 entry and aligned commercial-readiness notes with the active V4 engineering line. No release, security certification, performance result, or registry publication is claimed.
7. **Local Markdown links:** the static link scan checked 79 first-party Markdown files (excluding `.git`, `target`, `vendor`, `.venv`, and `artifact-archive`) and found no missing local link targets.

## Current source facts reflected in documentation

- The workspace contains six Rust crate manifests: `nexusq-core`, `nexusq-cli`, `nexusq-server`, `nexusq-c`, `nexusq-py`, and `nexusq-kernels`.
- The active branch is `v4/issue-23-kernel-work`, with PR #46 targeting `nexusqv4`.
- `nexusq-kernels` contains scalar Keccak-f[1600]/SHAKE128/SHAKE256 and ML-KEM reference operations, a backend contract, a routed API, and CPU-capability reporting. Only the scalar backend is selectable; optimized SIMD/assembly implementations are not present as selectable backends.
- Phase 0 measurement plumbing and a 1.5x per-operation median/p95 gate exist in source. Their current-head acceptance outcome is deliberately not stated here; it requires review of the exact CI artifact/report.
- The repository workflow directory currently contains `ci.yml`, `sdk-ci.yml`, `benchmarks.yml`, and `pqc-arena.yml`.

## Deliberately not changed

- Historical V1/V2/V3 benchmark numbers, archived artifact manifests, and dated forensic findings.
- The historical V1 roadmap (`docs/ROADMAP.md`) and version-specific V2 documents, which are explicitly labeled historical/frozen.
- Third-party/vendor README and license documentation.
- Performance/security acceptance checkboxes: source presence alone is not evidence of correctness, constant-time behavior, or performance.

## Ongoing documentation rule

Update the live V4 tracker, root README status, changelog, and relevant technical docs whenever code or acceptance evidence changes. Mark a phase complete only when its documented evidence exists for the relevant source revision.

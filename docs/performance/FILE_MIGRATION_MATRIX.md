# V4 → Native Assembly Initiative: File Migration Matrix

This matrix records intended treatment. “Candidate” means the content still requires review against the current base and dependencies before import; it is not a statement that the file is already migrated.

| File or group | Decision | Reason / action |
|---|---|---|
| `README.md` | Adapt | Point active V4 performance work to Issue #48; preserve V1–V3 history and avoid stale status claims. |
| `BENCHMARKS.md` | Keep + adapt | Preserve methodology and previous results; distinguish historical values from new gate evidence. |
| `CHANGELOG.md` | Keep | Preserve history; add entries only when the new line has actual changes. |
| `SECURITY.md` | Review | Keep security policy; do not overstate assurance or claim new assembly is audited. |
| `docs/V3_V4_ROADMAP.md` | Historical | Keep unmodified under `history/`; active plan is this roadmap. |
| `docs/V4_ISSUE_23_EXECUTION.md` | Historical reference | Preserve previous task/evidence record; do not use as the new active checklist. |
| `docs/V4_PHASE0_MEASUREMENT_CONTRACT.md` | Keep as reference | Reuse valid measurement requirements after checking against the new harness. |
| `docs/V4_ARENA_BASELINE_AUDIT.md` | Keep as reference | Preserve findings and caveats about baseline measurement. |
| `docs/V4_ISSUE_23_CODE_AUDIT_2026-10-15.md` | Historical | Keep dated conclusions; revisit any current-code claims. |
| `docs/V4_ISSUE_23_COMPARATIVE_KERNEL_AUDIT_2026-10-15.md` | Historical + technical reference | Reuse source map and hypotheses; do not present hypotheses as measured attribution. |
| `docs/OBSERVABILITY.md` | Review | Reuse artifact and metadata practices when still compatible. |
| `docs/COMMERCIAL_READINESS.md` | Leave unchanged initially | Not part of the kernel-performance scope. |
| `arena/adapters/aws-lc/runner.c` | Candidate to reuse | Improved sample distributions are valuable; add/verify all nine operations and ensure comparable boundaries. |
| `arena/runners/nexusq/src/main.rs` | Candidate to reuse | Preserve sample-level output and metadata; verify direct production path and operation coverage. |
| `arena/runners/nexusq/src/bin/hybrid_benchmark.rs` | Review separately | Keep only if it serves the required production-path contract. |
| `arena/runners/nexusq/Cargo.toml` and `Cargo.lock` | Adapt with harness | Dependencies must resolve to the exact code under test; do not import without matching source and feature wiring. |
| `arena/protocol.md` | Keep + adapt | Preserve schema/measurement definitions; explicitly document wrapper costs. |
| `arena/schemas/benchmark-result.schema.json` | Keep + version if needed | Validate every emitted row and required metadata. |
| `arena/adapters/aws-lc/README.md` | Keep + adapt | Preserve pinned source/build instructions and limitations. |
| `artifact-archive/**` | Preserve as history | Keep raw evidence, hashes and manifests; never treat old results as new results. |
| `crates/nexusq-kernels/**` | Selective code review | Reuse valid scalar oracle/API/tests; previous intrinsics are baseline candidates, not proof of assembly performance. |
| `vendor/ml-kem/**` | Selective code review | Keep source provenance and correct call sites; recheck all arithmetic and feature gates. |
| `vendor/ml-dsa/**` | Candidate to import selectively/whole if required | Preserve upstream licenses and commit; review changes and test vectors. |
| `vendor/module-lattice/**` | Preserve/inspect | ML-DSA arithmetic dependencies must stay version-consistent. |
| `.github/workflows/ci.yml` from old PR | Do not import wholesale | It replaces/deletes unrelated workflows; new CI must be additive and focused. |
| `.github/workflows/pqc-arena.yml` | Reuse selected logic | Existing matrix includes unnecessary comparators; extract only required NEXUS-Q/AWS-LC work after verifying contracts. |
| Security, fuzz, SDK and release workflows | Preserve | Specialized performance CI must not remove repository-wide gates. |
| `.github/workflows/v4-issue23-phase0.yml` | Review | Preserve useful provenance logic if needed; do not keep duplicate triggers unnecessarily. |
| `vercel.json` | Keep separate | Deployment configuration is unrelated to assembly performance. |
| Archived benchmark/profile reports | Preserve | Keep source revision, CPU/toolchain metadata and checksums. |

## Import rule
Files are imported only in a dedicated commit after their dependencies and tests are identified. A file is not considered “kept” merely because it is copied; it must be referenced by the active build, documentation or evidence workflow.

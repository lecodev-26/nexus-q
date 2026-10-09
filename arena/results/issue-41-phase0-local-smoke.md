# Issue #41 — Phase 0 local harness smoke test

**Status:** local harness smoke test and hosted CI comparison passed. The PR remains open pending review of all Phase 0 acceptance criteria.

## Hosted CI evidence (2026-10-09)

- [PQC Benchmark Arena run #34](https://github.com/lecodev-26/nexus-q/actions/runs/37895517814) — all executed jobs passed.
- [NEXUS-Q V3 Incremental CI run #7](https://github.com/lecodev-26/nexus-q/actions/runs/37895517862) — both jobs passed.
- The CI validated 90 records for V1, 90 for V1+zeroize, and 100 for V3; all matched the JSON Schema and signing sample contract.
- Across 10 randomized rounds and the same 64 signing seeds, matched-seed latency ratios (candidate / V1) were: V1+zeroize min/median/max = 0.9887 / 1.0015 / 1.0157; V3 = 0.9998 / 1.0014 / 1.0177.
- Interpretation: V3 median ratio 1.0014 is approximately 0.14% slower than V1 in this dataset. This is descriptive evidence, not proof of performance equivalence or a release performance guarantee.
- Artifacts: [V1 JSONL](https://github.com/lecodev-26/nexus-q/actions/runs/37895517814/artifacts/11600271953), [V1+zeroize JSONL](https://github.com/lecodev-26/nexus-q/actions/runs/37895517814/artifacts/11600097486), [V3 JSONL](https://github.com/lecodev-26/nexus-q/actions/runs/37895517814/artifacts/11600660639).

## Environment

- Host: Termux / Android, `aarch64-linux-android`
- Compiler: `rustc 1.98.1 (48a229cea 2026-09-01)`
- Runner: release profile, local patched `vendor/ml-kem` and `vendor/module-lattice`
- Workload: ML-DSA-65, fixed message, deterministic corpus of 64 seeds, 5 timed signatures per seed, 10 warmups per seed
- Repetitions: 2 independent runner invocations

## Results

| Measurement | Run 1 | Run 2 |
|---|---:|---:|
| Total timed signing samples | 320 | 320 |
| Aggregate median latency | 1,642,769 ns | 1,669,231 ns |
| Aggregate p95 latency | 4,034,154 ns | 4,034,846 ns |
| Aggregate standard deviation | 1,230,553.57 ns | 1,223,728.3 ns |

The 64 seed IDs matched exactly between runs. For the per-seed median latency ratio (run 2 / run 1), the observed distribution was:

- Minimum: **0.946**
- Median: **1.002**
- p95: **1.025**
- Maximum: **1.065**

The runner emitted 10 JSONL records in the current feature-enabled smoke test, including a separate cached-verifier record with 50 timed samples. JSON parsing, expected record count, 64-seed/320-sample structure, and cached-verifier sample count passed.

## Interpretation and limits

This confirms deterministic seed-corpus matching and validates the new sample/statistics shape on the local device. The median of per-seed ratios was 1.002 (about 0.2% difference), with observed per-seed ratios from 0.946 to 1.065. The device is not an isolated benchmark host, and these two runs do **not** establish a release performance claim or replace the planned ten randomized alternating CI rounds. The hosted workflow JSON Schema validation and three-way V1 / V1+zeroize / V3 comparison passed in the linked CI run. The later SHA-3 zeroize A/B diagnostic is documented separately in `issue-41-phase1-sha3-zeroize-diagnostic.md`.

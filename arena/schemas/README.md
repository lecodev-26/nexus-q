# Arena schemas

benchmark-result.schema.json is the normalized result contract.

The registry JSON files are intentionally simple and are validated by CI. Generated reports must consume registry/result data rather than duplicate benchmark facts.

## Reproducible ML-DSA-65 signing measurements (Arena harness v2)

The NEXUS-Q runner's `sign` record uses a fixed corpus of 64 deterministic
benchmark seeds (`seed-000` through `seed-063`) and records five timed
signatures per seed after ten warmups for each key. The seed expansion is a
public SplitMix64 fixture generator, not a source of production key material.
All V1, V1+zeroize, and current-runner comparisons use the same corpus and
message, allowing per-seed ratios rather than comparing unrelated random keys.

`measurement.samples_ns` retains all per-operation samples. `measurement.statistics`
contains sample count, minimum, median, p95, and population standard deviation;
`measurement.seed_samples` contains the corresponding samples and statistics
for every deterministic seed. The cached `MlDsa65VerifyingKey::verify` path is
emitted as a separate `verify` record when the `cached-verifier` runner feature
is enabled.

The CI reference job pins Rust 1.98.1, builds with `--locked`, and runs ten
randomized alternating rounds of three variants: the unmodified `v1.0.0`
reference, that same V1 source with only the ML-DSA `zeroize` dependency feature
enabled, and the current V3 runner. JSONL artifacts retain the toolchain string,
Cargo lockfile SHA-256, commit, CPU/features, readable frequency/governor,
optimization profile, and per-run order. Frequency/governor fields may be
unavailable on hosted runners and are then explicitly marked `unknown` or null.

Benchmark records are evidence, not a performance claim by themselves. Compare
matched-seed distributions and repeated-run statistics; do not infer a crypto
regression from a single-key signing latency or optimize until the Phase 0
measurement gate is reviewed.

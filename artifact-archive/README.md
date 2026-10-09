# NEXUS-Q artifact archive

This directory preserves generated research and benchmark evidence in the Git repository so it remains available even after GitHub Actions retention expires.

## Snapshot captured on 2026-10-09

### Existing repository artifacts (V2)

The files from the existing `artifacts/v2/` tree are copied without modification under `repository-artifacts/v2/`:

- `v2/v2-01/nexusq-local.jsonl`
- `v2/v2-02/local-profile.tsv`
The tracked source tree currently contains these two files; no additional files under `artifacts/v2/v2-02/perf/` were present in the source tree at the time of this snapshot.

### GitHub Actions archives: V1, V1+zeroize, V3 and adapters

Raw ZIP files downloaded from [PQC Benchmark Arena run #34](https://github.com/lecodev-26/nexus-q/actions/runs/37895517814) and [NEXUS-Q V3 Incremental CI run #7](https://github.com/lecodev-26/nexus-q/actions/runs/37895517862) are stored in `workflow-artifacts/2026-10-09/`.

| Local archive | GitHub artifact ID | Contents / purpose |
|---|---:|---|
| `pqc-arena-v1-reference.zip` | 11600271953 | V1 reference benchmark JSONL |
| `pqc-arena-v1-zeroize-reference.zip` | 11600097486 | V1 with zeroization reference JSONL |
| `pqc-arena-nexusq-reference.zip` | 11600660639 | V3/NEXUS-Q benchmark JSONL |
| `pqc-arena-botan-3.13.0.zip` | 11600512120 | Botan adapter output |
| `pqc-arena-pq-code-package.zip` | 11600500397 | PQ Code Package adapter output |
| `pqc-arena-liboqs-0.16.0.zip` | 11600431251 | liboqs adapter output |
| `pqc-arena-rustcrypto-kems.zip` | 11600161983 | RustCrypto KEM adapter output |
| `pqc-arena-aws-lc-ec05f25.zip` | 11599868300 | AWS-LC adapter output |
| `pqc-arena-circl-1.6.4.zip` | 11599819790 | CIRCL adapter output |
| `pqc-arena-openssl-3.5.9.zip` | 11599294834 | OpenSSL adapter output |
| `v3-fast-validation.zip` | 11600156994 | V3 fast-validation artifact |
| `v3-arena-diagnostic.zip` | 11599683754 | V3 Arena diagnostic artifact |

The original artifacts can also be inspected from the linked Actions runs. GitHub's retention expiry applies to the Actions copies; this repository copy is versioned with Git.

## Benchmark context

The archived run validated 90 V1 records, 90 V1+zeroize records and 100 V3 records. ML-DSA-65 signing comparisons used the same 64-seed corpus across 10 randomized rounds. The matched-seed latency ratio (candidate / V1) median was 1.0015 for V1+zeroize and 1.0014 for V3. These are measurements from that specific CI environment, not universal performance guarantees.

## Integrity and interpretation

- The ZIP files are preserved byte-for-byte as downloaded from the connector-provided artifact files.
- `SHA256SUMS-2026-10-09.txt` contains local hashes for integrity checks.
- Keep raw ZIPs as the source of record; unpacked or transformed data should be treated as derived material.
- Do not compare benchmark values across different CPUs, compilers, feature sets or harness versions without accounting for environment metadata.

## Scope note

This is the initial V1/V2/V3 archive snapshot. It captures all currently tracked files under the repository's `artifacts/v2/` directory and the listed V1/V3 CI artifacts from the identified runs. Historical V2 GitHub Actions artifacts from other runs must be enumerated and added separately if they are still available; this README intentionally does not claim that every historical Actions artifact has already been recovered.

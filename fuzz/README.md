# NEXUS-Q Rust fuzzing

This directory contains the standalone `cargo-fuzz` workspace. The targets exercise parsers, decoders, key material import, policy deserialization, and backup import. The harness implementations are intentionally kept separate from this operational guide; changes to harness semantics and auditor reproducibility are tracked independently.

## Target inventory

| Target | Surface |
| --- | --- |
| `vault_parse` | Vault file opening and parsing |
| `envelope_parse` | Envelope deserialization and KEM-backed opening |
| `vault_body_decode` | Vault body decoding |
| `audit_event_decode` | Audit event deserialization |
| `audit_segment_decode` | Audit segment binary decoding |
| `credential_decode` | Credential decoding and public-key verification |
| `backup_import` | Encrypted backup import |
| `mldsa_key_decode` | ML-DSA-65 verifying-key decoding |
| `policy_set_decode` | Policy-set JSON deserialization |

The target list is registered in `Cargo.toml`. Keep this inventory synchronized when targets are added or removed.

## Requirements and local commands

Install Rust nightly and `cargo-fuzz`:

```sh
rustup toolchain install nightly --component rust-src
cargo install cargo-fuzz --locked
```

Build every target:

```sh
cd fuzz
cargo +nightly fuzz build
```

Run one target for a bounded campaign:

```sh
cargo +nightly fuzz run vault_parse corpus/vault_parse -- -max_total_time=600 -timeout=30
```

Replace `vault_parse` with any target in the inventory. Omit the corpus argument to let libFuzzer create its default corpus. Run a single target at a time when reproducing a finding, and preserve the exact command, toolchain, commit SHA, and input artifact.

## Corpus and continuous campaigns

Each target has an independent corpus at `fuzz/corpus/<target>/`. The scheduled GitHub Actions workflow runs each target for **10 minutes per weekly campaign** (and can also be started manually). It restores and updates a per-target GitHub Actions cache, then uploads the resulting corpus and libFuzzer artifacts as run artifacts. The cache is an optimization, not the archival record: download the run artifact before changing or clearing cache keys.

The initial corpus directories may be empty. libFuzzer grows them from generated inputs; no hand-authored seed coverage or coverage percentage is claimed here. The workflow run page and its retained artifacts are the historical campaign record. Artifacts are retained for 90 days by the workflow; preserve any security-relevant crash outside that retention window.

## Crash retention and triage

1. Download the `fuzz-campaign-<target>` artifact and preserve the crashing input unchanged.
2. Record the target, repository commit SHA, workflow run URL, toolchain, libFuzzer command, and crash/sanitizer output.
3. Reproduce against that exact commit and input using the command above. Do not overwrite the original artifact.
4. Open a private security report for suspected vulnerabilities; otherwise create an issue with the minimized reproducer where disclosure is safe.
5. Fix the defect and add a regression test or permanent corpus regression input where appropriate. Re-run the target and record the successful follow-up run.
6. Keep the original crash, minimized reproducer, triage decision, and fix reference linked from the issue/PR. Do not silently delete a crash or classify an untriaged crash as harmless.

## Findings and measured results

No campaign measurements or historical findings are asserted by this document. Use the dated GitHub Actions campaign runs and their artifacts as the source of truth; update this section only with results verified from those runs. A completed campaign with no crash is evidence only for that target, commit, duration, and configuration—not proof of absence of vulnerabilities.

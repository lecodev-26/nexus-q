# NEXUS-Q fuzzing

This directory is a standalone [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
workspace containing nine libFuzzer harnesses for NEXUS-Q's untrusted-input
boundaries: parsers, decoders, key-material import, policy deserialization, and
backup import. It is an independent Cargo workspace (see `Cargo.toml`), so the
main workspace's `cargo test --workspace` and its Rust 1.88 pin do not cover or
apply to it.

This guide is written so that an auditor starting from a clean checkout can
build every harness, run bounded campaigns, and reproduce crashes retained by
CI. Fuzzing here is an internal engineering gate, not an independent security
audit; see [Limitations](#limitations).

## Harness inventory

Targets are registered as `[[bin]]` entries in `Cargo.toml`; sources live in
`fuzz_targets/`. Keep this inventory synchronized when targets are added or
removed. `cargo +nightly fuzz list` (run from `fuzz/`) prints the registered
targets.

### Parsers

| Target | What the harness exercises | Campaigns |
| --- | --- | --- |
| `vault_parse` | `Vault::open` on arbitrary bytes written to a temporary file — vault file opening and parsing | Weekly 10-minute matrix; manual 4-hour soak |
| `envelope_parse` | CBOR deserialization of `Envelope`, plus full envelope opening via `open_envelope_with_kem` with a fixed hybrid KEM key | Weekly 10-minute matrix; manual 4-hour soak |
| `backup_import` | `backup::import` on inputs carrying the `NQB1` magic prefix, using fixed fuzz passwords | Weekly 10-minute matrix; manual 4-hour soak |

### Vault and storage decoders

| Target | What the harness exercises | Campaigns |
| --- | --- | --- |
| `vault_body_decode` | `VaultBody` deserialization | Weekly 10-minute matrix |
| `audit_event_decode` | `AuditEvent` deserialization | Weekly 10-minute matrix |
| `audit_segment_decode` | `AuditSegment::from_bytes` binary decoding | Weekly 10-minute matrix |
| `credential_decode` | `Credential` deserialization and `verify_with_public_key` with fixed 32-byte and 1952-byte dummy keys | Weekly 10-minute matrix |

### Cryptographic key decoding

| Target | What the harness exercises | Campaigns |
| --- | --- | --- |
| `mldsa_key_decode` | `MlDsa65VerifyingKey::from_public_key`, including malformed lengths | Weekly 10-minute matrix |

### Policies

| Target | What the harness exercises | Campaigns |
| --- | --- | --- |
| `policy_set_decode` | `PolicySet` JSON deserialization | Weekly 10-minute matrix |

Note (verified 2026-11-24): `mldsa_key_decode` campaigns currently record no
new corpus units — every generated input takes the same early rejection path
in `MlDsa65VerifyingKey::from_public_key`, so a 30-second local run and the
2026-11-23 weekly run both ended with an empty on-disk corpus and the weekly
run uploaded no `fuzz-campaign-mldsa_key_decode` artifact. The job still
builds and executes the harness for its full 10 minutes; the absence of an
artifact for this target does not mean the job was skipped.

Every harness feeds untrusted bytes to one decode/parse path and must not
panic; malformed input must be rejected with an error, not a crash. Harnesses
use only fixed, public fuzz values (for example the `0x42…` hybrid key seed in
`envelope_parse` and the `fuzz-backup-password`/`fuzz-vault-password` pair in
`backup_import`). No real keys, passwords, or vault data are involved, so
legitimate corpus and crash artifacts contain no key material.

## Toolchain requirements

- **Rust nightly with the `rust-src` component.** cargo-fuzz builds harnesses
  with sanitizer instrumentation via `-Zbuild-std`, which requires nightly and
  `rust-src`:

  ```sh
  rustup toolchain install nightly --component rust-src
  ```

- **cargo-fuzz:**

  ```sh
  cargo install cargo-fuzz --locked
  ```

- **A C toolchain for linking** (for example `build-essential` on
  Debian/Ubuntu).

Verified from a clean checkout on 2026-11-24 (Linux x86_64). Nightly floats;
the recorded version is what the verification run used:

- `rustc 1.102.0-nightly (20fe935d5 2026-11-23)`
- `cargo-fuzz 0.13.2`
- `gcc (Debian 14.2.0-19) 14.2.0`

## Build

From the repository root of a clean checkout:

```sh
cd fuzz
cargo +nightly fuzz build                 # all nine harnesses
cargo +nightly fuzz build vault_parse     # or a single harness
```

Building generates `fuzz/Cargo.lock` and `fuzz/target/` locally; neither is
committed — both are covered by `.gitignore`.

## Run a bounded campaign

Run from `fuzz/`. Create the corpus and artifact directories first — libFuzzer
requires the `-artifact_prefix` directory to exist:

```sh
mkdir -p corpus/vault_parse artifacts/vault_parse
cargo +nightly fuzz run vault_parse corpus/vault_parse -- \
  -max_total_time=600 \
  -timeout=30 \
  -artifact_prefix=artifacts/vault_parse/ \
  -print_final_stats=1
```

These are the same flags the weekly CI matrix uses. `-max_total_time` is in
seconds; use `-max_total_time=30` for a 30-second smoke run. Replace
`vault_parse` with any target from the inventory.

New corpus inputs accumulate in `corpus/<target>/`. Crash, timeout, OOM, and
leak reproducers are written to `artifacts/<target>/` as `crash-<sha1>`,
`timeout-<sha1>`, `oom-<sha1>`, or `leak-<sha1>`.

## Seed corpus

- `fuzz/corpus/<target>/` is each target's local corpus. libFuzzer starts from
  it, mutates its entries, and adds interesting new inputs back to it.
- **No corpus is committed to git.** The initial directories do not exist in a
  clean checkout; they are created on demand and are covered by `.gitignore`
  (`fuzz/corpus/`, `fuzz/artifacts/`). Crash artifacts and corpus entries must
  never be committed (see `CONTRIBUTING.md` §3).
- The weekly workflow preserves corpora across runs in a per-target GitHub
  Actions cache and uploads the corpus with each run's artifact (90-day
  retention). The cache is an optimization, not the archival record: download
  the run artifact before changing or clearing cache keys.
- The four-hour soak runs **without** an on-disk corpus (no corpus argument),
  so each soak campaign starts from libFuzzer's empty-corpus state.
- Do not add hand-authored seed inputs containing real keys, vaults,
  credentials, or personal data. Corpus entries must never expose secrets or
  sensitive data.

## CI campaigns

Two workflows run these harnesses; see also `docs/ci-pipeline.md`.

### Weekly matrix — `.github/workflows/fuzz-nightly.yml`

- Schedule: weekly, Mondays 02:17 UTC (cron `17 2 * * 1`), plus manual
  `workflow_dispatch`. The file is named `fuzz-nightly.yml` for historical
  reasons; the configured schedule is weekly.
- One parallel job per target (all nine), each a single 10-minute libFuzzer
  run with `-max_total_time=600 -timeout=30
  -artifact_prefix=artifacts/<target>/ -print_final_stats=1` and
  `corpus/<target>/` as the on-disk corpus. Job timeout: 25 minutes.
- The corpus is restored from and saved to a per-target Actions cache.
- After every run (`if: always()`), the corpus and any crash artifacts upload
  as the `fuzz-campaign-<target>` artifact (90-day retention). The artifact
  contains `corpus/<target>/`, plus `artifacts/<target>/` when the run
  produced reproducers. If a target's corpus stayed empty and nothing crashed,
  no files match and no artifact is uploaded for that target (the upload step
  logs a "No files were found" warning).

### Four-hour sequential soak — `.github/workflows/fuzz-soak.yml`

- Manual `workflow_dispatch` only.
- A `fuzz-build` job first compiles all nine harnesses
  (`cargo fuzz build`) as a compile gate.
- Three campaign jobs then run **sequentially** — `vault_parse`, then
  `envelope_parse`, then `backup_import`, each `needs:` the previous one. Each
  campaign is a single libFuzzer invocation with `-max_total_time=14400`
  (4 hours) and `-timeout=30`; the job timeout is 255 minutes. Because each
  job requires the previous job's success, a crash in an earlier target skips
  the remaining campaigns in that run.
- Campaign output is streamed live and simultaneously bounded to the most
  recent 10 MiB on disk.

Each campaign produces this layout in the runner workspace:

```
fuzz-results/<target>/run-<run-id>-attempt-<attempt>/
├── artifacts/          libFuzzer reproducers (crash-*, timeout-*, oom-*, leak-*)
├── logs/
│   └── libfuzzer.log   bounded log (most recent 10 MiB)
├── command.txt         exact campaign command
├── exit_status.txt     libFuzzer exit status
├── started_at.txt      UTC start timestamp
└── report.json         machine-readable summary (schema_version 1)
```

`report.json` records the outcome (`completed`, `crash`, `failed`, or
`interrupted`), the issue kinds found, the crash reproducer paths, the final
libFuzzer statistics, the exact command, the exit status, the rustc and
cargo-fuzz versions used, and any finalization warnings. Classification is
evidence-based: a missing `exit_status.txt` means `interrupted`; exit status 0
means `completed`; a non-zero exit with a `crash-*`/`timeout-*`/`oom-*`/`leak-*`
artifact means `crash`; any other non-zero exit means `failed`.

After every campaign (`if: always()`), the results directory uploads as the
`fuzz-soak-<target>-run-<run-id>-attempt-<attempt>` artifact (90-day
retention); the downloaded artifact contains the
`run-<run-id>-attempt-<attempt>/` directory. Retention is best-effort: if
GitHub terminates the runner (job timeout, cancellation, runner loss),
finalization and upload may not run at all. libFuzzer's 240-minute limit
leaves ~15 minutes of headroom inside the 255-minute job timeout, which makes
runner loss unlikely in practice.

## Reproducing a crash from a CI artifact

1. Find the campaign run on the Actions tab, or list runs:

   ```sh
   gh run list --repo lecodev-26/nexus-q --workflow fuzz-nightly.yml
   gh run list --repo lecodev-26/nexus-q --workflow fuzz-soak.yml
   ```

2. Download the run's artifact from the run page, or with:

   ```sh
   # weekly matrix artifact
   gh run download <run-id> --repo lecodev-26/nexus-q \
     --name fuzz-campaign-<target> --dir repro
   # soak artifact
   gh run download <run-id> --repo lecodev-26/nexus-q \
     --name fuzz-soak-<target>-run-<run-id>-attempt-<attempt> --dir repro
   ```

   Use a named `--dir` directory: at least gh 2.46.0 fails with a spurious
   "path traversal" error when downloading into `--dir .`.

3. Locate the reproducer: `artifacts/<target>/crash-<sha1>` inside a weekly
   artifact, or `run-<run-id>-attempt-<attempt>/artifacts/crash-<sha1>` inside
   a soak artifact. A soak `report.json` lists them under
   `crash_reproducers`.

4. Check out the exact commit the campaign ran (shown on the run page, and
   recorded as `commit_sha` in a soak `report.json`):

   ```sh
   git checkout <commit-sha>
   ```

5. Reproduce the single input (runs just that input, once):

   ```sh
   cd fuzz
   cargo +nightly fuzz run <target> /path/to/crash-<sha1>
   ```

   A genuine crash reproduces the libFuzzer/sanitizer failure output and exits
   non-zero.

6. Minimize a copy of the reproducer:

   ```sh
   cargo +nightly fuzz tmin <target> /path/to/crash-<sha1>
   ```

   `-minimize_crash` only applies to inputs that actually crash. Against a
   non-crashing input, `tmin` produces no minimized artifact and exits
   non-zero with `ERROR: the input <file> did not crash`.

7. Record the target, commit SHA, workflow run URL, toolchain versions
   (`rustc +nightly --version`, `cargo +nightly fuzz --version`), the exact
   command, and the full crash output. Do not modify or overwrite the original
   reproducer; minimize a copy.

If the crash does not reproduce on the recorded commit and toolchain, record
that fact in the triage notes instead of assuming the artifact is stale.

## Handling crash inputs and corpus data

- Treat every crash input and corpus entry as untrusted data. Never commit
  them (`CONTRIBUTING.md` §3); `.gitignore` covers the default locations
  (`fuzz/corpus/`, `fuzz/artifacts/`, `fuzz-results/`).
- Crash inputs, corpus entries, logs, and reproducer commands must never
  expose secrets or sensitive data. The harnesses use fixed public fuzz values
  only, so legitimate artifacts contain no key material; if a finding ever
  involves real secret data, treat it as a security incident.
- Suspected vulnerabilities must be reported privately per `SECURITY.md`. Do
  not open public issues, PRs, or discussions containing reproducers, crash
  inputs, or exploit details.
- After a fix, add a regression test in the affected crate. Do not commit the
  crash input itself.

## Related work tracked separately

- Extending four-hour soak coverage to the remaining six targets: tracked in
  [discussion #175](https://github.com/lecodev-26/nexus-q/discussions/175).
- Building the fuzz targets in PR CI: tracked in
  [discussion #181](https://github.com/lecodev-26/nexus-q/discussions/181).

Neither is implemented by this document; check the discussions for current
status.

## Limitations

- A completed campaign with no crash is evidence only for that target, commit,
  duration, toolchain, and configuration — not proof of the absence of
  vulnerabilities.
- Fuzzing concentrates on parsing and decoding boundaries. It does not replace
  the workspace test suite, dependency audits, or an independent security
  audit. NEXUS-Q does not claim production readiness, an external audit, or
  certification; see `SECURITY.md` and `docs/SECURITY_MODEL.md`.
- `docs/V2_SECURITY_FUZZING.md` describes the historical V2-era gate. This
  README and the two workflows above describe the current state.

# crates.io 4.1.1 Artifact Inventory

**Checked:** 2026-10-25, read-only. This is registry evidence, not an assertion that the 4.1.1 ecosystem is one coherent release.

## Method

For each workspace crate, read the version entry from the public crates.io sparse index, downloaded the exact `.crate` archive from `static.crates.io`, and computed SHA-256. The downloaded archive digest matched the sparse-index `cksum` for all 17 listed crates. The package's embedded `.cargo_vcs_info.json` was also read to record Cargo's source revision (`git.sha1`) and path in the repository. That file is package metadata, not a signed source-to-build attestation; it is evidence of the recorded packaging revision, not independent proof every file was built from that commit.

## Results

| Crate | Version | SHA-256 (matches sparse index) | `.cargo_vcs_info` commit | Published `rust_version` | Registry dependency entries |
|---|---:|---|---|---:|---:|
| `nexusq` | 4.1.1 | `0ef7eaf74d92dbd0a4beba8e4c0c7fa51284e20995d9267444b60f4358566b2e` | `c0899e4` | 1.85 | 4 |
| `nexusq-core` | 4.1.1 | `5fd10cc5f60d3464157ccdb6606849851b5131ea07591a28c1c1817f8a21f379` | `5dd564d` | 1.85 | 31 |
| `nexusq-ml-dsa` | 4.1.1 | `b6d343dd103dccf4b5d82b7d67e8355f4fc5f7919ededcbe56be83d2508e8193` | `5dd564d` | 1.85 | 18 |
| `nexusq-ml-kem` | 4.1.1 | `fd2082775625fed2d55b1f4895b8c08e584c429c6627981ee9ea014e07344062` | `5dd564d` | 1.85 | 16 |
| `nexusq-kernels` | 4.1.1 | `25edf8ae451750ed16ad917d8be54c92720219408d8b2683777e5faf2f722a4d` | `5dd564d` | 1.85 | 2 |
| `nexusq-cli` | 4.1.1 | `6eeddaa9cbbd3a2c06ccf796b4c44fd1f47aef7567742033c251e00c46e49732` | `c0899e4` | 1.85 | 8 |
| `nexusq-server` | 4.1.1 | `48d90cf6c660a6f51f5cbeb32993e7e40fd4b2b1a1e59e6f336f2c0be1944f41` | `c0899e4` | 1.85 | 12 |
| `nexusq-c` | 4.1.1 | `63c4375e7965de1d64a39389f93780bada0676dd2ca77f665c1aaa3d2ecd96e5` | `c0899e4` | 1.85 | 2 |
| `nexusq-py` | 4.1.1 | `279f884702cf51729080a176454b1b3fb08fcc9f4db2a12c350e965d79d0bd45` | `c0899e4` | 1.85 | 3 |
| `nexusq-x509` | 4.1.1 | `123e98425bcc450693e63ae0e644c67a91d980f06ab90ed082b947291d0b483c` | `5dd564d` | 1.85 | 11 |
| `nexusq-ocsp` | 4.1.1 | `1a145bbf1e3f0926c48adc84a49e2cc010148a8c3f552b9dabaf8213c3682e7b` | `3f8dfb7` | 1.85 | 18 |
| `nexusq-ha` | 4.1.1 | `ca4763ae49fe8c12c23b16d98a4a24c2a2cc029a97393c291494364dd10cfa0a` | `5dd564d` | 1.85 | 5 |
| `nexusq-enrollment` | 4.1.1 | `5810fb39533d6ac20af01dfab2d9aea14d4b363ce4a3643dcd9144151488ccc0` | `5dd564d` | 1.85 | 26 |
| `nexusq-hsm` | 4.1.1 | `d4cce0198e4f59f606ccf4c77e6064ff3efbf932ac8d68c0839cba7d2a41925b` | `c0899e4` | 1.85 | 15 |
| `nexusq-tsa` | 4.1.1 | `61944348459718177bc118160b74bc819956e55c56d049479be57897690d6d18` | `5dd564d` | 1.85 | 10 |
| `nexusq-pki-cluster` | 4.1.1 | `71a1c94df9d9946a0ce83fb10ecf651d88d3fe663db470998b28f6e221a758be` | `38701d5` | 1.88 | 20 |
| `nexusq-admin` | 4.1.1 | `ff63d892bb1e8125c5c0a77cc9d258351a2901c42773cba2c56878c42f30ff6f` | `5dd564d` | 1.85 | 12 |

## Interpretation

The crate packages do **not** all record one source commit. The embedded metadata records four source revisions:

- `5dd564d…`: 9 crates, matching the commit in the verified GitHub release attestation.
- `c0899e4…`: 6 crates (`nexusq`, `nexusq-cli`, `nexusq-server`, `nexusq-c`, `nexusq-py`, `nexusq-hsm`); this commit is on the `work/4.1.1-development` line and is a child of `3f8dfb…`.
- `3f8dfb…`: `nexusq-ocsp`, a child of `5dd564d…`.
- `38701d5…`: `nexusq-pki-cluster`, a child of `5b8a663…` on the main/docs line.

This gives at least four recorded source snapshots for crates.io version `4.1.1`, even though all 17 published archive hashes match the public registry index. That is direct evidence that version equality does not mean source-commit equality.

A read-only diff review narrows the code impact of those four recorded revisions:

- `3f8dfb7…` differs from `5dd564d…` only in workflow naming/configuration; no Rust crate source diff was found.
- `c0899e4…` differs from `3f8dfb7…` in two Rust files: enrollment and TSA serial allocation replace `AtomicU64::fetch_update` with a `SeqCst` load, checked increment and `compare_exchange_weak` retry loop. Static inspection indicates the same checked monotonic increment semantics (including overflow failure); this change is not itself evidence of altered cryptographic behavior.
- `38701d5…` has no `crates/` source diff from its parent `5b8a663…`; it is a docs-only descendant for the files checked.

Thus the four source identifiers remain a real provenance/versioning discrepancy, but the source diffs inspected here are narrow and appear behavior-preserving rather than four independent implementations. This review does not replace a package-by-package reproducible build or signed provenance.

The registry reports `rust_version = 1.85` for 16 of these crates and `1.88` for `nexusq-pki-cluster`. The repository's current workspace declares Rust 1.88, while the release-attested source commit `5dd564d…` declares 1.85. This is a release-history distinction, not necessarily a defect in every crate; confirm actual MSRV per package and align docs/workflows before making one workspace-wide compatibility claim. The release workflow in the current PR branch is pinned to Rust 1.88 and the PR fast workflow uses floating `stable`; neither is a per-crate minimum-version matrix. Local tests for kernels/TSA/enrollment passed under Rust 1.99.1, but exact 1.85/1.88 MSRV runs were not available in this environment.

## Archive-to-source spot comparison

The downloaded archives were also compared byte-for-byte against the Git tree named by each archive's `.cargo_vcs_info.json`. For all 17 crates, every mapped non-lock package file compared successfully: **194 exact file matches across the set**. The comparison excluded Cargo's normalized `Cargo.toml`, generated `.cargo_vcs_info.json` and `.cargo-ok`; it mapped and compared `Cargo.toml.orig` against the original manifest. Each archive's packaged `Cargo.lock` differed from the root workspace lockfile at the recorded commit; these archive lockfiles are package-scoped and have different dependency closures, so byte equality is not expected. Their generation should still be reproduced from the recorded commits before closing the evidence item. No other package files were unmapped in this check.

This means the published Rust package contents are consistent with their recorded source snapshots for the files compared, while the snapshots themselves differ across the 17 crate names. It does not establish that those four source snapshots should have shared one version, and `.cargo_vcs_info.json` remains self-reported metadata rather than a signed source attestation.

The `dependencies` count above is the number of direct dependency entries in each sparse-index version record, not a count of unique transitive dependencies or a substitute for an SBOM.

## Audit follow-up

- [x] Compare mapped source/package files against each recorded commit: 194 non-lock files matched byte-for-byte across all 17 crates.
- [ ] Reproduce package-scoped `Cargo.lock` generation and complete a reproducible, normalized manifest comparison from each recorded commit.
- [x] Diff the four `.cargo_vcs_info` source revisions against each other: `3f8dfb7…` has no Rust crate source changes from `5dd564d…`; `c0899e4…` changes only the two checked atomic serial loops; `38701d5…` has no `crates/` diff from `5b8a663…`. This narrows code impact but does not resolve source-identity/provenance mismatch.
- [ ] Reconcile the release-attested commit with the four `.cargo_vcs_info` revisions and the separate npm/NuGet/Packagist metadata.
- [ ] Decide the intended Rust MSRV contract per crate and update package metadata, workspace declarations, CI, and documentation consistently in a separately reviewed change.
- [ ] Generate a complete dependency SBOM from the resolved lockfile/build inputs and include dependency relationships; the published CycloneDX file currently lists only 17 internal workspace crates and zero dependency relationships.
- [ ] Do not republish crates, yank versions, or change tags as part of this inventory.

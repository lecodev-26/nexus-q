# Partial publication recovery runbook

Status: operational procedure; does not authorize publishing NEXUS-Q 4.1.1.

## Stop conditions

If `publicar.sh`, a registry CLI, or a release workflow fails after any publication may have started:

1. Stop. Do not immediately rerun the full publisher.
2. Preserve the complete `.publish-dist/publish-*.log`, terminal output, workflow URL, and UTC time of the failure. Do not attach credentials or environment dumps.
3. Do not retry a timed-out upload until the registry's authoritative version endpoint has been queried. A timeout can happen after the registry accepted the upload.
4. Keep the exact approved commit, tag target, artifact digests, and provenance evidence fixed. A partial upload is not permission to retag, overwrite, or rebuild under the same version.
5. If the affected artifact's source identity or digest cannot be established, mark that destination `unknown` and stop there pending maintainer review.

## Build a reconciliation ledger

Create a fresh ledger for each recovery attempt, outside the repository if it may contain private operational details. Record one row per artifact/channel with these fields:

- UTC observation time and operator
- registry/channel and exact package/artifact/version
- authoritative registry URL or API used
- state: `present-matching`, `present-mismatch`, `absent`, or `unknown`
- published file digest, where retrievable, and expected digest
- source commit/ref and provenance evidence
- action taken and resulting registry receipt/workflow URL

Never infer `absent` from a timeout, authentication error, rate limit, malformed response, or server error. Use `unknown` and retry the read-only lookup later. Keep credentials, tokens, signed upload URLs, and private signing material out of the ledger.

## Reconcile in this order

1. **GitHub Release and runtime assets** — inspect the existing release and every asset; compare names, sizes, SHA-256 digests, attestation subjects, source commit, and tag target. Do not upload with overwrite/clobber semantics. An existing asset with a mismatching digest is `present-mismatch`, not an invitation to replace it.
2. **crates.io** — inspect each of the 18 entries handled by `.github/scripts/publish_crates.py` (17 workspace crates plus `nexusq-native-backend`) independently. Confirm exact version and dependency order. Existing versions cannot be replaced; do not infer their source identity from the version string alone.
3. **PyPI** — inspect the exact distribution filenames and hashes. `twine --skip-existing` prevents some duplicate uploads but does not prove that an existing file matches the intended build.
4. **npm** — query the exact package/version and compare the published tarball's contents/integrity to the reviewed build. Do not republish an existing version.
5. **RubyGems** — query the exact version and compare the downloaded gem's digest/content where available.
6. **pub.dev** — query the exact package/version and inspect the published archive/content. Do not treat an HTTP or auth error as absence.
7. **Packagist** — determine whether this is a repository metadata refresh or a new package-version discovery. A successful refresh response is not proof that every source file or release artifact matches the approved commit.
8. **Maven Central** — check `nexusq` and `nexusq-kotlin` independently. Inspect the exact coordinates and available artifact checksums/signatures. A successful deployment of one artifact does not establish the state of the other.
9. **NuGet** — inspect the package version and its uploaded files separately from the GitHub Actions dispatch result. `--skip-duplicate` is not source-provenance verification.
10. **Go and SwiftPM** — verify the exact tag each ecosystem resolves and compare it to the approved source commit. These channels are Git-tag-based rather than ordinary registry uploads.

## Decision rules

- `present-matching`: mark complete only after content and source identity are adequately verified.
- `present-mismatch`: stop. Do not overwrite, delete, yank, retag, or issue a replacement under the same version without explicit maintainer approval and a documented incident/release decision.
- `absent`: eligible for a separately reviewed publish action only after the release identity is approved and every prerequisite for that channel passes.
- `unknown`: stop; resolve the lookup uncertainty before any mutation.

Do not mark a channel complete merely because a command returned exit code zero. Capture the registry's resulting version/artifact and verify it independently when possible.

## Resume requirements

The current `publicar.sh` is a sequential multi-registry publisher, not a transaction manager. It has no durable per-channel checkpoint ledger and does not make all cross-registry operations atomic. Some destinations have duplicate-skip behavior; that is a collision guard, not a complete resume protocol. Therefore:

- Do not blindly rerun the full script after a partial failure.
- Do not enable `NEXUSQ_RELEASE_IDENTITY_APPROVED`, set the matching local approval variables, or dispatch release workflows merely to get past a recovery gate. These approvals must represent a separate, explicit decision about the exact release identity.
- Publish only an explicitly selected missing channel using a reviewed, channel-specific procedure. If the existing script cannot safely target that channel independently, stop and prepare a code change or a maintainer-reviewed manual procedure first.
- Record every mutation and re-run read-only reconciliation afterward.

## Current 4.1.1 caution

This runbook does not resolve the documented `4.1.1` / `v4.1.1` source-identity discrepancy. The historical attestation and the current tag target must be reconciled by a maintainer before any new publication or recovery upload. Do not modify tags or already-published artifacts as part of reconciliation without explicit approval.

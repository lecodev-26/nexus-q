# NEXUS-Q operational artifacts

Phase 19 packages the release as a platform-specific archive without requiring
a package manager, container runtime, or init system.

## Release build

From the repository root:

    cargo build --workspace --release

The operational binaries are:

- target/release/nexusq — CLI.
- target/release/nexusq-server — HTTP server.

Other workspace outputs may be produced by Cargo, but they are not part of the
server deployment artifact unless a future release profile explicitly adds
them.

## Packaging

Run:

    ./deploy/package-release.sh

An optional output directory can be supplied:

    ./deploy/package-release.sh /path/to/output

The script creates:

    nexusq-v<VERSION>-<TARGET>.tar.gz
    nexusq-v<VERSION>-<TARGET>.tar.gz.sha256

The archive contains:

    bin/nexusq
    bin/nexusq-server
    config/nexusq-server.env.example
    docs/DEPLOYMENT.md
    docs/SERVER.md
    ARTIFACTS.txt
    SHA256SUMS

The archive is assembled with normalized tar metadata and a fixed archive
member timestamp. This makes the archive layout and metadata deterministic
for a given set of input bytes; the binaries themselves still depend on the
toolchain and build environment.

## Secret boundary

The packaging script deliberately excludes:

- populated environment files;
- bearer tokens;
- vault files;
- private keys;
- generated logs;
- local state.

nexusq-server.env.example contains placeholders only.

Never place production secrets into the release staging directory.

## Installation model

The archive is intentionally package-manager neutral. A deployment may unpack
the binaries under a platform-specific application directory and keep
configuration, mutable vault state, and logs outside the application tree.

The deployment service may be managed by a native supervisor, an init system,
or another process manager appropriate to the platform. NEXUS-Q does not
require Docker or systemd.

## Operational interface

After startup, the server exposes:

- /health — liveness.
- /readyz — readiness.
- /metrics — Prometheus-style operational metrics.

The corresponding /v1/health and /v1/ready endpoints are also available.
The metrics and management surfaces must remain inside the intended monitoring
and deployment trust boundary.

## Verification

Verify the archive checksum before installation:

    sha256sum -c nexusq-v<VERSION>-<TARGET>.tar.gz.sha256

Then verify the package-internal checksums after extraction:

    cd nexusq-v<VERSION>-<TARGET>
    sha256sum -c SHA256SUMS

The deployment environment must separately provision the vault and bearer
token before starting nexusq-server.
NEXUSQ_SERVER_TOKEN must contain at least 32 bytes.
NEXUSQ_VAULT_PATH must point to the intended vault.
NEXUSQ_SERVER_ADDR defaults to loopback.
NEXUSQ_TRUSTED_TLS_TERMINATION=1 is required before a non-loopback bind.
nexusq-server does not terminate TLS itself.

## Publication boundary

This packaging flow is local/release preparation only. It does not publish
GitHub repositories, crates, PyPI packages, SDK packages, or a v1.0 release.
Those actions remain after Phase 22 and the final CI/release gates.

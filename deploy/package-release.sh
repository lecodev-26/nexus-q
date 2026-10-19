#!/bin/sh
set -eu

# Assemble a local release artifact without publishing it.
# Usage:
#   ./deploy/package-release.sh
#   ./deploy/package-release.sh /path/to/output
#
# The script expects release binaries produced by:
#   cargo build --workspace --release
#
# It packages only deployment-relevant, non-secret artifacts.

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT_DIR/dist"}
VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -n 1)
TARGET_TRIPLE=${NEXUSQ_PACKAGE_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}
PACKAGE_NAME="nexusq-v$VERSION-$TARGET_TRIPLE"

if [ -z "$VERSION" ] || [ -z "$TARGET_TRIPLE" ]; then
    echo "error: unable to determine version or target triple" >&2
    exit 1
fi

for binary in nexusq nexusq-server; do
    if [ ! -x "$ROOT_DIR/target/release/$binary" ]; then
        echo "error: missing release binary: target/release/$binary" >&2
        echo "run: cargo build --workspace --release" >&2
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"
STAGING=$(mktemp -d "$OUTPUT_DIR/.nexusq-package.XXXXXX")
cleanup() {
    rm -rf "$STAGING"
}
trap cleanup EXIT HUP INT TERM

PACKAGE_DIR="$STAGING/$PACKAGE_NAME"
mkdir -p "$PACKAGE_DIR/bin" "$PACKAGE_DIR/lib" "$PACKAGE_DIR/include" "$PACKAGE_DIR/config" "$PACKAGE_DIR/docs"

cp "$ROOT_DIR/target/release/nexusq" "$PACKAGE_DIR/bin/nexusq"
cp "$ROOT_DIR/target/release/nexusq-server" "$PACKAGE_DIR/bin/nexusq-server"

# Ship the C ABI runtime and header alongside the CLI/server artifact. The
# release workflow builds the workspace first, including nexusq-c.
NATIVE_LIBRARY=
for candidate in libnexusq.so libnexusq.dylib nexusq.dll; do
    if [ -f "$ROOT_DIR/target/release/$candidate" ]; then
        NATIVE_LIBRARY=$candidate
        break
    fi
done
if [ -z "$NATIVE_LIBRARY" ]; then
    echo "error: missing C SDK runtime in target/release (expected libnexusq.so, libnexusq.dylib, or nexusq.dll)" >&2
    echo "run: cargo build -p nexusq-c --release" >&2
    exit 1
fi
cp "$ROOT_DIR/target/release/$NATIVE_LIBRARY" "$PACKAGE_DIR/lib/$NATIVE_LIBRARY"
cp "$ROOT_DIR/crates/nexusq-c/include/nexusq.h" "$PACKAGE_DIR/include/nexusq.h"
cp "$ROOT_DIR/deploy/nexusq-server.env.example" "$PACKAGE_DIR/config/nexusq-server.env.example"
cp "$ROOT_DIR/docs/DEPLOYMENT.md" "$PACKAGE_DIR/docs/DEPLOYMENT.md"
cp "$ROOT_DIR/docs/SERVER.md" "$PACKAGE_DIR/docs/SERVER.md"

printf '%s\n' \
    'NEXUS-Q release artifact' \
    "version: $VERSION" \
    "target: $TARGET_TRIPLE" \
    '' \
    'Contents:' \
    '  bin/nexusq' \
    '  bin/nexusq-server' \
    '  lib/' \
    '  include/nexusq.h' \
    '  config/nexusq-server.env.example' \
    '  docs/DEPLOYMENT.md' \
    '  docs/SERVER.md' \
    '' \
    'No populated environment file, vault, bearer token, private key, or generated log is included.' \
    'The example environment file contains placeholders only.' \
    > "$PACKAGE_DIR/ARTIFACTS.txt"

(
    cd "$PACKAGE_DIR"
    sha256sum \
        bin/nexusq \
        bin/nexusq-server \
        "lib/$NATIVE_LIBRARY" \
        include/nexusq.h \
        config/nexusq-server.env.example \
        docs/DEPLOYMENT.md \
        docs/SERVER.md \
        ARTIFACTS.txt > SHA256SUMS
)

ARCHIVE="$OUTPUT_DIR/$PACKAGE_NAME.tar.gz"
tar -cf - -C "$STAGING" \
    --sort=name \
    --mtime='UTC 1970-01-01' \
    --owner=0 --group=0 --numeric-owner \
    "$PACKAGE_NAME" | gzip -n > "$ARCHIVE"

sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"

printf '%s\n' "Release artifact created:"
printf '  %s\n' "$ARCHIVE"
printf '  %s\n' "$ARCHIVE.sha256"
printf '%s\n' "Archive contents:"
tar -tzf "$ARCHIVE"

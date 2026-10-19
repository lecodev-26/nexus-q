#!/usr/bin/env bash
# Download and verify the version-matched default RustCrypto runtime, then run
# a Dart command with NEXUSQ_LIBRARY set for this process.
set -euo pipefail
VERSION="4.1.0"
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS/$ARCH" in
  Linux/x86_64|Linux/amd64) TARGET="x86_64-unknown-linux-gnu"; LIB="libnexusq.so" ;;
  Linux/aarch64|Linux/arm64) TARGET="aarch64-unknown-linux-gnu"; LIB="libnexusq.so" ;;
  Darwin/arm64|Darwin/aarch64) TARGET="aarch64-apple-darwin"; LIB="libnexusq.dylib" ;;
  *) echo "NEXUS-Q Dart FFI prebuilt runtime is unavailable for $OS/$ARCH; build/install a compatible library and set NEXUSQ_LIBRARY." >&2; exit 2 ;;
esac
if [[ "$OS" == Linux ]] && ldd --version 2>&1 | head -n 1 | grep -qi musl; then
  echo "NEXUS-Q prebuilt Linux runtime requires glibc, not musl/Alpine." >&2
  exit 2
fi
if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <dart command> [arguments...] (for example: $0 dart run example/smoke.dart)" >&2
  exit 2
fi
if [[ -n "${NEXUSQ_LIBRARY:-}" ]]; then exec "$@"; fi

BASE="https://github.com/lecodev-26/nexus-q/releases/download/v${VERSION}"
ARCHIVE="nexusq-sdk-runtime-${TARGET}.tar.gz"
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/nexusq/${VERSION}/${TARGET}"
RUNTIME_DIR="${CACHE_ROOT}/nexusq-sdk-runtime-${TARGET}"
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'
  fi
}
verify_runtime() {
  [[ -f "$RUNTIME_DIR/runtime.json" && -f "$RUNTIME_DIR/SHA256SUMS" && -f "$RUNTIME_DIR/lib/$LIB" ]] || return 1
  python3 - "$RUNTIME_DIR/runtime.json" "$TARGET" <<'PY' || return 1
import json,sys
m=json.load(open(sys.argv[1]))
assert m.get('target') == sys.argv[2] and m.get('provider') == 'rustcrypto' and m.get('experimental') is False, m
PY
  (cd "$RUNTIME_DIR" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi) >/dev/null
}
if ! verify_runtime; then
  mkdir -p "$CACHE_ROOT"
  TEMP="$(mktemp -d)"
  trap 'rm -rf "$TEMP"' EXIT
  curl -fsSL --connect-timeout 10 --max-time 30 "$BASE/NATIVE-RUNTIME-SHA256SUMS" -o "$TEMP/release-sums"
  curl -fsSL --connect-timeout 10 --max-time 120 "$BASE/$ARCHIVE" -o "$TEMP/$ARCHIVE"
  EXPECTED="$(awk -v file="$ARCHIVE" '$2 == file {print $1}' "$TEMP/release-sums")"
  [[ -n "$EXPECTED" ]] || { echo "No release checksum found for $ARCHIVE" >&2; exit 1; }
  ACTUAL="$(sha256_file "$TEMP/$ARCHIVE")"
  [[ "${ACTUAL,,}" == "${EXPECTED,,}" ]] || { echo "SHA-256 mismatch for $ARCHIVE" >&2; exit 1; }
  tar -xzf "$TEMP/$ARCHIVE" -C "$TEMP"
  NEW_DIR="$TEMP/nexusq-sdk-runtime-$TARGET"
  [[ -d "$NEW_DIR" ]] || { echo "Runtime archive has an unexpected layout" >&2; exit 1; }
  python3 - "$NEW_DIR/runtime.json" "$TARGET" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
assert m.get('target') == sys.argv[2] and m.get('provider') == 'rustcrypto' and m.get('experimental') is False, m
PY
  (cd "$NEW_DIR" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi)
  rm -rf "$RUNTIME_DIR"
  mv "$NEW_DIR" "$RUNTIME_DIR"
fi
export NEXUSQ_LIBRARY="$RUNTIME_DIR/lib/$LIB"
exec "$@"

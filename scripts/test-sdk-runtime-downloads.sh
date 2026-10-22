#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMP="$(mktemp -d)"
SERVER_PID=""
VENDOR="$ROOT/bindings/typescript/vendor/libnexusq.so"
if [[ -f "$VENDOR" ]]; then cp "$VENDOR" "$TEMP/original-vendor-lib.so"; fi
cleanup() {
  [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
  chmod -R u+w "$TEMP" 2>/dev/null || true
  rm -rf "$TEMP"
  if [[ -f "$TEMP/original-vendor-lib.so" ]]; then cp "$TEMP/original-vendor-lib.so" "$VENDOR"; else rm -f "$VENDOR"; fi
  rm -f "$VENDOR.download"
}
trap cleanup EXIT
FIXTURE="$TEMP/fixture"
mkdir -p "$FIXTURE" "$TEMP/cache"
cp "$ROOT/target/release/libnexusq.so" "$FIXTURE/nexusq-sdk-runtime-linux-x64.so"
(cd "$FIXTURE" && sha256sum nexusq-sdk-runtime-linux-x64.so > NATIVE-RUNTIME-SHA256SUMS)
PORT=18765
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$FIXTURE" >"$TEMP/http.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$PORT/NATIVE-RUNTIME-SHA256SUMS" >/dev/null 2>&1 && break
  sleep 1
done
export NEXUSQ_TEST_RUNTIME_BASE_URL="http://127.0.0.1:$PORT/"
export XDG_CACHE_HOME="$TEMP/cache"
(cd "$ROOT/bindings/go" && CGO_ENABLED=0 go run ./examples/smoke)
(cd "$ROOT/bindings/dart" && dart run example/smoke.dart)
(cd "$ROOT/bindings/typescript" && npm run build && node scripts/postinstall.cjs && npm run smoke)
echo 'Go, Dart, and TypeScript verified first-use runtime download, SHA-256, cache, and smoke operation.'

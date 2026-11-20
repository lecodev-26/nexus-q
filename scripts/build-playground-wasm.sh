#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack is required. Install it from https://rustwasm.github.io/wasm-pack/installer/" >&2
  exit 1
fi
wasm-pack build crates/nexusq-wasm --target web --release --out-dir "$ROOT/site/playground/pkg" --out-name nexusq_wasm
printf '\nWASM browser package created at site/playground/pkg\n'

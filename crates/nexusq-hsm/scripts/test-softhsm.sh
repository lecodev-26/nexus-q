#!/usr/bin/env bash
set -euo pipefail

command -v softhsm2-util >/dev/null || { echo "softhsm2-util is required" >&2; exit 2; }
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 2; }
module="${SOFTHSM2_MODULE:-}"
if [[ -z "$module" ]]; then
  for candidate in /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so; do
    if [[ -f "$candidate" ]]; then module="$candidate"; break; fi
  done
fi
[[ -n "$module" && -f "$module" ]] || { echo "Set SOFTHSM2_MODULE to libsofthsm2.so" >&2; exit 2; }
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/tokens"
cat > "$root/softhsm2.conf" <<CONF
 log.level = ERROR
 objectstore.backend = file
 directories.tokendir = $root/tokens
 slots.removable = false
CONF
export SOFTHSM2_CONF="$root/softhsm2.conf"
export NEXUSQ_PKCS11_MODULE="$module"
export NEXUSQ_PKCS11_PIN="nexusq-test-pin-$(printf '%s' "$$" | sha256sum | cut -c1-8)"
export NEXUSQ_PKCS11_SLOT_INDEX=0
softhsm2-util --init-token --free --label NexusQTest --so-pin "nexusq-so-pin-$(printf '%s' "$$" | sha256sum | cut -c1-8)" --pin "$NEXUSQ_PKCS11_PIN" >/dev/null
cargo test -p nexusq-hsm --features softhsm-tests --test softhsm -- --nocapture

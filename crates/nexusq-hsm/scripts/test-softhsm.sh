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
proxy_pid=""
cleanup() {
  if [[ -n "$proxy_pid" ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT
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
cargo test -p nexusq-hsm --features softhsm-tests --test softhsm --locked softhsm_keeps_aes256_key_non_extractable_and_performs_gcm_inside_token -- --nocapture

# Provision a non-extractable AES-256 key and create a disposable proxy config.
export NEXUSQ_XKS_KEY_LABEL="nexusq-xks-ci-key"
export NEXUSQ_XKS_EXTERNAL_KEY_ID="nexusq-xks-ci-key"
export NEXUSQ_XKS_CONFIG="$root/xks-config.json"
export NEXUSQ_XKS_BIND="127.0.0.1:9443"
export XKS_TEST_ACCESS_KEY_ID="BETWEEN2TENAND3TENCHARACTERS"
export XKS_TEST_SECRET_ACCESS_KEY="PleaseReplaceThisWithSomeSecretOfLength43To64"
cargo run -p nexusq-xks-proxy --example provision-aes-key --locked > "$root/key-mapping.json"
export NEXUSQ_XKS_KEY_LABEL="nexusq-xks-health-key"
export NEXUSQ_XKS_EXTERNAL_KEY_ID="nexusq-xks-health-key"
cargo run -p nexusq-xks-proxy --example provision-aes-key --locked > "$root/health-key-mapping.json"
health_key_ref="$(jq -c '.keyRef' "$root/health-key-mapping.json")"
jq -n \
  --arg uriPath "/example/uri/path/prefix/kms/xks/v1" \
  --arg accessKeyId "$XKS_TEST_ACCESS_KEY_ID" \
  --arg secretAccessKey "$XKS_TEST_SECRET_ACCESS_KEY" \
  --arg pkcs11Module "$NEXUSQ_PKCS11_MODULE" \
  --arg pkcs11Pin "$NEXUSQ_PKCS11_PIN" \
  --argjson healthCheckKeyRef "$health_key_ref" \
  --slurpfile mapping "$root/key-mapping.json" \
  '{uriPath:$uriPath,accessKeyId:$accessKeyId,secretAccessKey:$secretAccessKey,pkcs11Module:$pkcs11Module,pkcs11SlotIndex:0,pkcs11Pin:$pkcs11Pin,ekmVendor:"SoftHSM",ekmModel:"SoftHSM2",healthCheckKeyRef:$healthCheckKeyRef,keys:[$mapping[0]]}' > "$NEXUSQ_XKS_CONFIG"
chmod 600 "$NEXUSQ_XKS_CONFIG"

cargo run -p nexusq-xks-proxy --locked > "$root/xks-proxy.log" 2>&1 &
proxy_pid=$!
status=""
for _ in $(seq 1 60); do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST --header 'Content-Type: application/json' --data '{}' \
    http://127.0.0.1:9443/example/uri/path/prefix/kms/xks/v1/health || true)"
  [[ "$status" == "401" ]] && break
  sleep 1
done
if [[ "$status" != "401" ]]; then
  cat "$root/xks-proxy.log" >&2
  echo "XKS proxy did not become ready (HTTP $status)" >&2
  exit 1
fi

# Run the official AWS sample conformance client against the local SoftHSM-backed proxy.
git clone --depth 1 https://github.com/aws-samples/aws-kms-xksproxy-test-client.git "$root/aws-xks-test-client"
(
  cd "$root/aws-xks-test-client"
  XKS_PROXY_HOST="127.0.0.1:9443" \
  URI_PREFIX="example/uri/path/prefix" \
  SIGV4_ACCESS_KEY_ID="$XKS_TEST_ACCESS_KEY_ID" \
  SIGV4_SECRET_ACCESS_KEY="$XKS_TEST_SECRET_ACCESS_KEY" \
  KEY_ID="$NEXUSQ_XKS_EXTERNAL_KEY_ID" \
  SCHEME= ANSI_ESCAPE=0 ./test-xks-proxy
)

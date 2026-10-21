#!/usr/bin/env bash
set -euo pipefail
exec "$(cd "$(dirname "$0")/.." && pwd)/crates/nexusq-hsm/scripts/test-softhsm.sh" "$@"

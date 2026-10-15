#!/usr/bin/env bash
# Constant-time check (ctgrind style) of the exact NEXUS-Q native build.
# - Compiles the same vendored sources and csrc/ configuration as build.rs, with
#   the libraries' own CT-testing hooks (MLK/MLD_CONFIG_CT_TESTING_ENABLED).
# - Marks all RNG output and all secret keys as undefined for valgrind memcheck;
#   any secret-dependent branch or memory index is reported as an error.
# - Negative control: a deliberate secret-dependent branch MUST be detected.
# - Coverage control: callgrind must show the AVX2 and s2n-bignum assembly ran.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; crate="$here/.."; vendor="$crate/../../vendor"
out="${1:-$here/out}"; mkdir -p "$out"
CC="${CC:-cc}"
F=(-O3 -fomit-frame-pointer -std=c99 -fno-strict-aliasing -g "-I$crate/csrc")
KEM=("-I$vendor/mlkem-native/mlkem" '-DMLK_CONFIG_FILE="nq_mlkem_config.h"' -DMLK_CONFIG_CT_TESTING_ENABLED)
DSA=("-I$vendor/mldsa-native/mldsa" '-DMLD_CONFIG_FILE="nq_mldsa_config.h"' -DMLD_CONFIG_CT_TESTING_ENABLED)
S2N=("-I$vendor/s2n-bignum" "-I$vendor/s2n-bignum/include")
$CC "${F[@]}" "${KEM[@]}" -c "$crate/csrc/nq_mlkem_all.c" -o "$out/kem.o"
$CC "${F[@]}" "${KEM[@]}" -c "$crate/csrc/nq_mlkem_asm.S" -o "$out/kemasm.o"
$CC "${F[@]}" "${KEM[@]}" "${S2N[@]}" -c "$crate/csrc/nq_keccak_x1.S" -o "$out/keccak.o"
$CC "${F[@]}" "${DSA[@]}" -c "$crate/csrc/nq_mldsa_all.c" -o "$out/dsa.o"
$CC "${F[@]}" "${DSA[@]}" -c "$crate/csrc/nq_mldsa_asm.S" -o "$out/dsaasm.o"
$CC "${F[@]}" "$here/ct_harness.c" "$out"/kem.o "$out"/kemasm.o "$out"/keccak.o "$out"/dsa.o "$out"/dsaasm.o -o "$out/ct_harness"
$CC -O1 -g "$here/neg.c" -o "$out/neg"

"$out/ct_harness"
echo "== valgrind memcheck (secrets undefined) =="
valgrind --error-exitcode=42 --track-origins=yes "$out/ct_harness" > "$out/ct-valgrind.log" 2>&1 || { cat "$out/ct-valgrind.log"; echo "FAIL: secret-dependent behaviour detected"; exit 1; }
grep "ERROR SUMMARY" "$out/ct-valgrind.log"

echo "== negative control (must be detected) =="
if valgrind --error-exitcode=42 "$out/neg" > "$out/neg.log" 2>&1; then
  cat "$out/neg.log"; echo "FAIL: negative control was NOT detected; harness is not effective"; exit 1
fi
grep -m1 "Conditional jump" "$out/neg.log"

echo "== coverage control: assembly actually executed under valgrind =="
valgrind --tool=callgrind --callgrind-out-file="$out/ct.callgrind" "$out/ct_harness" > /dev/null 2>&1
callgrind_annotate "$out/ct.callgrind" > "$out/ct.callgrind.txt" 2>/dev/null
for sym in nq_sha3_keccak_f1600 keccak_f1600_x4_avx2_asm nq_mlkem_poly_ntt nq_mldsa65_poly_ntt rej_uniform_avx2_asm; do
  if grep -q "$sym" "$out/ct.callgrind.txt"; then echo "executed: $sym"; else echo "FAIL: $sym not executed"; exit 1; fi
done
echo "CT CHECK PASSED"

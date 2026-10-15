#!/usr/bin/env bash
# Build the in-process A/B diagnostic. Our C sources use exactly the flags of build.rs.
# usage: diag/run.sh AWSLC_SRC AWSLC_BUILD OUTDIR [extra CFLAGS for the NEXUS-Q objects...]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; crate="$here/.."; vendor="$crate/../../vendor"
src="$1"; bld="$2"; out="$3"; shift 3; mkdir -p "$out"
CC="${CC:-cc}"
F=(-O3 -fomit-frame-pointer -std=c99 -fno-strict-aliasing -fPIC -ffunction-sections -fdata-sections -g "-I$crate/csrc" "$@")
KEM=("-I$vendor/mlkem-native/mlkem" '-DMLK_CONFIG_FILE="nq_mlkem_config.h"')
DSA=("-I$vendor/mldsa-native/mldsa" '-DMLD_CONFIG_FILE="nq_mldsa_config.h"')
S2N=("-I$vendor/s2n-bignum" "-I$vendor/s2n-bignum/include")
$CC "${F[@]}" "${KEM[@]}" -c "$crate/csrc/nq_mlkem_all.c" -o "$out/kem.o"
$CC "${F[@]}" "${KEM[@]}" -c "$crate/csrc/nq_mlkem_asm.S" -o "$out/kemasm.o"
$CC "${F[@]}" "${KEM[@]}" "${S2N[@]}" -c "$crate/csrc/nq_keccak_x1.S" -o "$out/keccak.o"
$CC "${F[@]}" "${KEM[@]}" "${S2N[@]}" -c "$crate/csrc/nq_keccak_x4.S" -o "$out/keccak4.o"
$CC "${F[@]}" "${DSA[@]}" -c "$crate/csrc/nq_mldsa_all.c" -o "$out/dsa.o"
$CC "${F[@]}" "${DSA[@]}" -c "$crate/csrc/nq_mldsa_asm.S" -o "$out/dsaasm.o"
$CC -O2 -g "$here/inproc_ab.c" "$out"/kem.o "$out"/kemasm.o "$out"/keccak.o "$out"/keccak4.o "$out"/dsa.o "$out"/dsaasm.o \
    "$bld/crypto/libcrypto.a" -lpthread -o "$out/inproc_ab"
echo "built $out/inproc_ab"

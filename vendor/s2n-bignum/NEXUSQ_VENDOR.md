# Vendored s2n-bignum (two Keccak routines)

- Upstream: https://github.com/awslabs/s2n-bignum
- Commit: `4b5f8214e85b6b239077c278825b7fa9c2ab9cf5`. This is the commit that
  AWS-LC `ec05f25ef5bcb1bf03d2e2f44ba57973a878e0ba` imports
  (`third_party/s2n-bignum/META.yml`).
- Imported files, unmodified:
  - `x86_att/sha3/sha3_keccak_f1600.S` (scalar Keccak-f1600, x86-64 baseline ISA)
  - `x86_att/sha3/sha3_keccak4_f1600_alt.S` (AVX2 4-way Keccak-f1600), added after
    perf profiles on AMD EPYC 7763 runners showed the upstream x4 routine and
    its call wrapper at 22.3 % of ML-KEM-768 decaps versus 20.2 % for this
    routine in AWS-LC (run 38796903942). AWS-LC selects it whenever AVX2 is
    available (`KeccakF1600_x4`). Wired through `MLK/MLD_USE_NATIVE_FIPS202_X4`
    with the same AVX2 capability check as upstream. HOL Light proof upstream:
    `x86/proofs/sha3_keccak4_f1600_alt.ml`. File license: Apache-2.0 OR ISC OR
    MIT-0. Byte-identical to AWS-LC's imported copy (checked in CI).
  - `include/_internal_s2n_bignum_x86_att.h` (assembler macros)
  - `LICENSE`, `NOTICE`
- Why: on x86-64, AWS-LC routes every 1-way Keccak-f1600 call of ML-KEM and
  ML-DSA to this exact routine (`crypto/fipsmodule/sha/keccak1600.c`,
  `KeccakF1600` -> `sha3_keccak_f1600`). Standalone mlkem-native and mldsa-native
  use their portable C permutation instead. Using the same routine removes the
  only remaining algorithmic difference against the comparator. It is wired in
  through the official `MLK_USE_NATIVE_FIPS202_X1` / `MLD_USE_NATIVE_FIPS202_X1`
  backend hooks (see `crates/nexusq-native-backend/csrc/nq_fips202_x86_64_*.h`).
- Assurance: functional correctness is proven in HOL Light upstream
  (`x86/proofs/sha3_keccak_f1600.ml`, `SHA3_KECCAK_F1600_SUBROUTINE_CORRECT`).
  The only branch is the public round counter. NEXUS-Q additionally checks it
  with differential tests and the valgrind constant-time harness.
- License: the file header is `SPDX-License-Identifier: Apache-2.0` (it derives
  from OpenSSL, written by Andy Polyakov). The repository-level license is
  Apache-2.0 OR ISC OR MIT-0. Binaries built with the `native-backend` crate
  therefore include Apache-2.0-only code and must carry `LICENSE`/`NOTICE`.
- The symbols are renamed at assembly time to `nq_sha3_keccak_f1600` and
  `nq_sha3_keccak4_f1600_alt` and made
  hidden (`S2N_BN_HIDE_SYMBOLS`), so it cannot clash with AWS-LC/aws-lc-rs when
  both are linked into one binary.

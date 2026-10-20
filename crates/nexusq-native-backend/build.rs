//! Builds the vendored mlkem-native / mldsa-native (pinned to the commits
//! imported by AWS-LC ec05f25e) plus the s2n-bignum scalar Keccak routine.
//!
//! The C sources are vendored INSIDE this crate (vendor/) so the crate is
//! self-contained and publishable; the repository-level vendor/ snapshot is
//! kept for upstream integrity diffing and must stay in sync (checked in CI).
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor = root.join("vendor");
    let mlkem = vendor.join("mlkem-native/mlkem");
    let mldsa = vendor.join("mldsa-native/mldsa");
    let s2n = vendor.join("s2n-bignum");
    let csrc = root.join("csrc");
    let portable = std::env::var("CARGO_FEATURE_PORTABLE_ONLY").is_ok();
    let c_keccak = std::env::var("CARGO_FEATURE_UPSTREAM_C_KECCAK").is_ok();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let native_x86 = !portable && arch == "x86_64" && os == "linux";
    let native_aarch64 = !portable && arch == "aarch64" && (os == "linux" || os == "android");
    let native = native_x86 || native_aarch64;

    // -O3 as in AWS-LC's CMake Release build. No -mavx2: AVX2 code lives only
    // in .S files and is selected at runtime (AVX2 && BMI2).
    let flags = [
        "-O3",
        "-fomit-frame-pointer",
        "-std=c99",
        "-fno-strict-aliasing",
        "-Wall",
        "-Wextra",
        "-Werror=incompatible-pointer-types",
        "-Werror=implicit-function-declaration",
        "-Werror=int-conversion",
    ];
    let mut kem = cc::Build::new();
    kem.include(&csrc)
        .include(&mlkem)
        .define("MLK_CONFIG_FILE", "\"nq_mlkem_config.h\"");
    let mut dsa = cc::Build::new();
    dsa.include(&csrc)
        .include(&mldsa)
        .define("MLD_CONFIG_FILE", "\"nq_mldsa_config.h\"");
    for b in [&mut kem, &mut dsa] {
        b.opt_level(3).warnings(false);
        for f in flags {
            b.flag_if_supported(f);
        }
        if portable {
            b.define("NQ_PORTABLE_ONLY", None);
        }
        if c_keccak {
            b.define("NQ_NO_S2N_KECCAK", None);
        }
    }
    kem.file(csrc.join("nq_mlkem_all.c"));
    dsa.file(csrc.join("nq_mldsa_all.c"));
    if native {
        // The upstream monolithic assembly translation units select the matching
        // x86-64 or AArch64 implementation from the target architecture macros.
        kem.file(csrc.join("nq_mlkem_asm.S"));
        dsa.file(csrc.join("nq_mldsa_asm.S"));
        if native_x86 && !c_keccak {
            // Shared by both libraries (identical permutation, one copy).
            kem.include(s2n.join("include"))
                .include(&s2n)
                .file(csrc.join("nq_keccak_x1.S"));
        }
    }
    kem.compile("nq_mlkem");
    dsa.compile("nq_mldsa");
    println!("cargo:rustc-cfg=nq_native_backend_compiled=\"{}\"", native);
    println!("cargo:rustc-check-cfg=cfg(nq_native_backend_compiled, values(\"true\", \"false\"))");
    for d in [&csrc, &mlkem, &mldsa, &s2n] {
        println!("cargo:rerun-if-changed={}", d.display());
    }
}

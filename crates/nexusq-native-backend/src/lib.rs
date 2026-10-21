//! NEXUS-Q native backend (experimental, isolated from the production crates).
//!
//! Safe Rust API (bytes in / bytes out, FIPS 203/204 contract) over the vendored
//! mlkem-native v2.0.0 (`d1b2fe78`) and mldsa-native v2.0.0 (`834a90d5`), the
//! same arithmetic cores that AWS-LC `ec05f25e` imports. On x86-64 Linux the
//! AVX2 assembly is selected at runtime (AVX2 && BMI2) and the 1-way Keccak
//! routine uses s2n-bignum; on AArch64, upstream NEON arithmetic and Keccak
//! assembly are selected for the mandatory Advanced SIMD execution state. The
//! portable C path remains available through `portable-only`. Secret material
//! is zeroized on drop.
#![deny(unsafe_op_in_unsafe_fn)]

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The OS CSPRNG failed.
    Rng,
    /// Wrong length or FIPS 203/204 input check failed (e.g. pk modulus check,
    /// dk hash check).
    InvalidInput,
    /// ML-DSA signature rejected.
    InvalidSignature,
    /// Any other non-zero return code from the native library.
    Native(i32),
}

/// RNG callback used by the C libraries: OS CSPRNG (getrandom(2)), no userspace state.
///
/// # Safety
/// `out` must be valid for writes of `len` bytes. Only the vendored C code calls this.
// SAFETY: exported under a NEXUS-Q-specific name for the vendored C code only;
// callers pass a writable buffer of exactly `len` bytes.
#[doc(hidden)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nq_randombytes(out: *mut u8, len: usize) -> i32 {
    if len == 0 {
        return 0;
    }
    if out.is_null() {
        return -1;
    }
    // SAFETY: the C callers pass a writable buffer of exactly `len` bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(out, len) };
    #[cfg(feature = "aws-lc-rng")]
    let result = aws_lc_rs::rand::fill(buf);
    #[cfg(not(feature = "aws-lc-rng"))]
    let result = getrandom::fill(buf);
    match result {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Map error codes shared by the ML-KEM and ML-DSA wrappers. Algorithm-specific
/// codes must not be conflated: for example, `-6` means ML-KEM PCT failure but
/// ML-DSA invalid signature. Verification maps its own result explicitly.
pub(crate) fn map_err(rc: i32) -> Error {
    match rc {
        -3 => Error::Rng,
        -4 | -5 | -7 | -9 => Error::InvalidInput,
        other => Error::Native(other),
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use super::{Error, map_err};

    #[test]
    fn algorithm_specific_minus_six_is_not_misclassified() {
        assert_eq!(map_err(-6), Error::Native(-6));
    }

    #[test]
    fn keccak_backend_metadata_matches_target_and_features() {
        let backend = super::keccak_x1_backend();
        if cfg!(all(
            target_arch = "x86_64",
            nq_native_backend_compiled = "true",
            not(feature = "upstream-c-keccak")
        )) {
            assert_eq!(backend, "s2n-bignum sha3_keccak_f1600 (x86-64 asm)");
        } else if cfg!(all(
            target_arch = "aarch64",
            nq_native_backend_compiled = "true"
        )) {
            assert_eq!(backend, "mlkem-native/mldsa-native AArch64 assembly");
        } else {
            assert_eq!(backend, "upstream portable C");
        }
    }
}

/// True when the AVX2 assembly backend was compiled in and is selected on this
/// CPU (same predicate as the C dispatch: AVX2 && BMI2).
pub fn native_backend_active() -> bool {
    #[cfg(all(target_arch = "x86_64", nq_native_backend_compiled = "true"))]
    {
        std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("bmi2")
    }
    #[cfg(not(all(target_arch = "x86_64", nq_native_backend_compiled = "true")))]
    {
        false
    }
}

/// Which 1-way Keccak-f1600 implementation is linked.
pub fn keccak_x1_backend() -> &'static str {
    if cfg!(all(
        target_arch = "x86_64",
        nq_native_backend_compiled = "true",
        not(feature = "upstream-c-keccak")
    )) {
        "s2n-bignum sha3_keccak_f1600 (x86-64 asm)"
    } else if cfg!(all(
        target_arch = "aarch64",
        nq_native_backend_compiled = "true"
    )) {
        "mlkem-native/mldsa-native AArch64 assembly"
    } else {
        "upstream portable C"
    }
}

macro_rules! mlkem_level {
    ($module:ident, $pk:expr, $sk:expr, $ct:expr,
     $kp:ident, $kpd:ident, $enc:ident, $encd:ident, $dec:ident) => {
        pub mod $module {
            use super::Error;
            use zeroize::{Zeroize, ZeroizeOnDrop};
            pub const PUBLIC_KEY_BYTES: usize = $pk;
            pub const SECRET_KEY_BYTES: usize = $sk;
            pub const CIPHERTEXT_BYTES: usize = $ct;
            pub const SHARED_SECRET_BYTES: usize = 32;

            // SAFETY: prototypes match mlkem_native.h v2.0.0 exactly; enforced at build
            // time by the ABI guard in csrc/nq_mlkem_all.c (-Werror=incompatible-pointer-types).
            unsafe extern "C" {
                fn $kp(pk: *mut u8, sk: *mut u8) -> i32;
                fn $kpd(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
                fn $enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
                fn $encd(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32;
                fn $dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
            }

            #[derive(Clone, PartialEq, Eq)]
            pub struct EncapsulationKey(pub [u8; PUBLIC_KEY_BYTES]);
            #[derive(Zeroize, ZeroizeOnDrop)]
            pub struct DecapsulationKey([u8; SECRET_KEY_BYTES]);
            #[derive(Zeroize, ZeroizeOnDrop)]
            pub struct SharedSecret([u8; SHARED_SECRET_BYTES]);
            #[derive(Clone, PartialEq, Eq)]
            pub struct Ciphertext(pub [u8; CIPHERTEXT_BYTES]);

            impl SharedSecret {
                pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
                    &self.0
                }
            }
            impl DecapsulationKey {
                pub fn as_bytes(&self) -> &[u8; SECRET_KEY_BYTES] {
                    &self.0
                }
                /// Length check only; the FIPS 203 hash check of dk runs inside every decapsulation.
                pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
                    Ok(Self(b.try_into().map_err(|_| Error::InvalidInput)?))
                }
                pub fn decapsulate(&self, ct: &Ciphertext) -> Result<SharedSecret, Error> {
                    let mut ss = SharedSecret([0; SHARED_SECRET_BYTES]);
                    // SAFETY: all buffers have the exact sizes required by the C API.
                    let rc = unsafe { $dec(ss.0.as_mut_ptr(), ct.0.as_ptr(), self.0.as_ptr()) };
                    if rc == 0 {
                        Ok(ss)
                    } else {
                        Err(super::map_err(rc))
                    }
                }
            }
            impl EncapsulationKey {
                /// Length check only; the FIPS 203 modulus check runs inside every encapsulation.
                pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
                    Ok(Self(b.try_into().map_err(|_| Error::InvalidInput)?))
                }
                pub fn encapsulate(&self) -> Result<(Ciphertext, SharedSecret), Error> {
                    let mut ct = Ciphertext([0; CIPHERTEXT_BYTES]);
                    let mut ss = SharedSecret([0; SHARED_SECRET_BYTES]);
                    // SAFETY: exact-size buffers.
                    let rc = unsafe { $enc(ct.0.as_mut_ptr(), ss.0.as_mut_ptr(), self.0.as_ptr()) };
                    match rc {
                        0 => Ok((ct, ss)),
                        _ => Err(super::map_err(rc)),
                    }
                }
                /// Deterministic variant for KAT/differential tests only.
                pub fn encapsulate_derand(
                    &self,
                    m: &[u8; 32],
                ) -> Result<(Ciphertext, SharedSecret), Error> {
                    let mut ct = Ciphertext([0; CIPHERTEXT_BYTES]);
                    let mut ss = SharedSecret([0; SHARED_SECRET_BYTES]);
                    // SAFETY: exact-size buffers.
                    let rc = unsafe {
                        $encd(
                            ct.0.as_mut_ptr(),
                            ss.0.as_mut_ptr(),
                            self.0.as_ptr(),
                            m.as_ptr(),
                        )
                    };
                    if rc == 0 {
                        Ok((ct, ss))
                    } else {
                        Err(super::map_err(rc))
                    }
                }
            }
            pub fn generate() -> Result<(DecapsulationKey, EncapsulationKey), Error> {
                let mut pk = EncapsulationKey([0; PUBLIC_KEY_BYTES]);
                let mut sk = DecapsulationKey([0; SECRET_KEY_BYTES]);
                // SAFETY: exact-size buffers.
                let rc = unsafe { $kp(pk.0.as_mut_ptr(), sk.0.as_mut_ptr()) };
                if rc == 0 {
                    Ok((sk, pk))
                } else {
                    Err(super::map_err(rc))
                }
            }
            /// Deterministic key generation from (d || z), FIPS 203 ML-KEM.KeyGen_internal.
            pub fn generate_derand(
                d_z: &[u8; 64],
            ) -> Result<(DecapsulationKey, EncapsulationKey), Error> {
                let mut pk = EncapsulationKey([0; PUBLIC_KEY_BYTES]);
                let mut sk = DecapsulationKey([0; SECRET_KEY_BYTES]);
                // SAFETY: exact-size buffers.
                let rc = unsafe { $kpd(pk.0.as_mut_ptr(), sk.0.as_mut_ptr(), d_z.as_ptr()) };
                if rc == 0 {
                    Ok((sk, pk))
                } else {
                    Err(super::map_err(rc))
                }
            }
        }
    };
}

mlkem_level!(
    mlkem768,
    1184,
    2400,
    1088,
    nq_mlkem768_keypair,
    nq_mlkem768_keypair_derand,
    nq_mlkem768_enc,
    nq_mlkem768_enc_derand,
    nq_mlkem768_dec
);
mlkem_level!(
    mlkem1024,
    1568,
    3168,
    1568,
    nq_mlkem1024_keypair,
    nq_mlkem1024_keypair_derand,
    nq_mlkem1024_enc,
    nq_mlkem1024_enc_derand,
    nq_mlkem1024_dec
);

pub mod mldsa65 {
    use super::Error;
    use zeroize::{Zeroize, ZeroizeOnDrop};
    pub const PUBLIC_KEY_BYTES: usize = 1952;
    pub const SECRET_KEY_BYTES: usize = 4032;
    pub const SIGNATURE_BYTES: usize = 3309;

    // SAFETY: prototypes match mldsa_native.h v2.0.0 exactly; enforced at build
    // time by the ABI guard in csrc/nq_mldsa_all.c (-Werror=incompatible-pointer-types).
    unsafe extern "C" {
        fn nq_mldsa65_keypair(pk: *mut u8, sk: *mut u8) -> i32;
        fn nq_mldsa65_keypair_internal(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
        fn nq_mldsa65_signature(
            sig: *mut u8,
            m: *const u8,
            mlen: usize,
            ctx: *const u8,
            ctxlen: usize,
            sk: *const u8,
        ) -> i32;
        fn nq_mldsa65_signature_internal(
            sig: *mut u8,
            m: *const u8,
            mlen: usize,
            pre: *const u8,
            prelen: usize,
            rnd: *const u8,
            sk: *const u8,
            externalmu: i32,
        ) -> i32;
        fn nq_mldsa65_verify(
            sig: *const u8,
            m: *const u8,
            mlen: usize,
            ctx: *const u8,
            ctxlen: usize,
            pk: *const u8,
        ) -> i32;
    }

    #[derive(Clone, PartialEq, Eq)]
    pub struct VerifyingKey(pub [u8; PUBLIC_KEY_BYTES]);
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct SigningKey([u8; SECRET_KEY_BYTES]);
    #[derive(Clone, PartialEq, Eq)]
    pub struct Signature(pub [u8; SIGNATURE_BYTES]);

    pub fn generate() -> Result<(SigningKey, VerifyingKey), Error> {
        let mut pk = VerifyingKey([0; PUBLIC_KEY_BYTES]);
        let mut sk = SigningKey([0; SECRET_KEY_BYTES]);
        // SAFETY: exact-size buffers.
        let rc = unsafe { nq_mldsa65_keypair(pk.0.as_mut_ptr(), sk.0.as_mut_ptr()) };
        if rc == 0 {
            Ok((sk, pk))
        } else {
            Err(super::map_err(rc))
        }
    }
    /// FIPS 204 ML-DSA.KeyGen_internal(xi).
    pub fn generate_from_seed(seed: &[u8; 32]) -> Result<(SigningKey, VerifyingKey), Error> {
        let mut pk = VerifyingKey([0; PUBLIC_KEY_BYTES]);
        let mut sk = SigningKey([0; SECRET_KEY_BYTES]);
        // SAFETY: exact-size buffers.
        let rc = unsafe {
            nq_mldsa65_keypair_internal(pk.0.as_mut_ptr(), sk.0.as_mut_ptr(), seed.as_ptr())
        };
        if rc == 0 {
            Ok((sk, pk))
        } else {
            Err(super::map_err(rc))
        }
    }
    impl SigningKey {
        pub fn as_bytes(&self) -> &[u8; SECRET_KEY_BYTES] {
            &self.0
        }
        pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
            Ok(Self(b.try_into().map_err(|_| Error::InvalidInput)?))
        }
        /// FIPS 204 ML-DSA.Sign, hedged (fresh 32-byte rnd from the OS CSPRNG), pure mode.
        pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> Result<Signature, Error> {
            if ctx.len() > 255 {
                return Err(Error::InvalidInput);
            }
            let mut sig = Signature([0; SIGNATURE_BYTES]);
            // SAFETY: exact-size sig/sk buffers; msg/ctx pointers valid for their lengths.
            let rc = unsafe {
                nq_mldsa65_signature(
                    sig.0.as_mut_ptr(),
                    msg.as_ptr(),
                    msg.len(),
                    ctx.as_ptr(),
                    ctx.len(),
                    self.0.as_ptr(),
                )
            };
            if rc == 0 {
                Ok(sig)
            } else {
                Err(super::map_err(rc))
            }
        }
        /// FIPS 204 deterministic variant (rnd = 0^32), pure mode. Used for differential tests.
        pub fn sign_deterministic(&self, msg: &[u8], ctx: &[u8]) -> Result<Signature, Error> {
            if ctx.len() > 255 {
                return Err(Error::InvalidInput);
            }
            let mut pre = Vec::with_capacity(2 + ctx.len());
            pre.push(0u8);
            pre.push(ctx.len() as u8);
            pre.extend_from_slice(ctx);
            let rnd = [0u8; 32];
            let mut sig = Signature([0; SIGNATURE_BYTES]);
            // SAFETY: as above.
            let rc = unsafe {
                nq_mldsa65_signature_internal(
                    sig.0.as_mut_ptr(),
                    msg.as_ptr(),
                    msg.len(),
                    pre.as_ptr(),
                    pre.len(),
                    rnd.as_ptr(),
                    self.0.as_ptr(),
                    0,
                )
            };
            if rc == 0 {
                Ok(sig)
            } else {
                Err(super::map_err(rc))
            }
        }
    }
    impl VerifyingKey {
        pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
            Ok(Self(b.try_into().map_err(|_| Error::InvalidInput)?))
        }
        /// FIPS 204 ML-DSA.Verify from the encoded public key (no cached expansion).
        pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), Error> {
            if ctx.len() > 255 {
                return Err(Error::InvalidInput);
            }
            let sig: &[u8; SIGNATURE_BYTES] =
                sig.try_into().map_err(|_| Error::InvalidSignature)?;
            // SAFETY: exact-size sig/pk buffers; msg/ctx valid for their lengths.
            let rc = unsafe {
                nq_mldsa65_verify(
                    sig.as_ptr(),
                    msg.as_ptr(),
                    msg.len(),
                    ctx.as_ptr(),
                    ctx.len(),
                    self.0.as_ptr(),
                )
            };
            if rc == 0 {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }
}

// Compile-time guarantee that every secret-bearing type zeroizes on drop.
#[allow(dead_code)]
fn _assert_zeroize_on_drop() {
    fn z<T: Zeroize + ZeroizeOnDrop>() {}
    z::<mlkem768::DecapsulationKey>();
    z::<mlkem768::SharedSecret>();
    z::<mlkem1024::DecapsulationKey>();
    z::<mlkem1024::SharedSecret>();
    z::<mldsa65::SigningKey>();
}

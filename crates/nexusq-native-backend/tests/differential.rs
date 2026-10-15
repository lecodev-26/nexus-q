//! Differential tests: native backend (mlkem-native/mldsa-native) vs the
//! RustCrypto code currently shipped by NEXUS-Q (vendor/ml-kem, vendor/ml-dsa).
//! Byte-for-byte equality on deterministic paths; cross-verification on
//! randomized paths; negative tests for FIPS 203/204 input checks.
#![allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::kem::{Decapsulate, KeyExport};
use nexusq_native_backend::{Error, mldsa65, mlkem768, mlkem1024};

fn rnd<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}
fn rnd_u32() -> u32 {
    u32::from_le_bytes(rnd::<4>())
}
fn iters() -> usize {
    std::env::var("NQ_DIFF_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

macro_rules! kem_diff {
    ($name:ident, $native:ident, $rs:ty, $rsct:ty) => {
        #[test]
        fn $name() {
            assert!(
                nexusq_native_backend::native_backend_active()
                    || cfg!(feature = "portable-only")
                    || !cfg!(target_arch = "x86_64")
            );
            for i in 0..iters() {
                let seed: [u8; 64] = rnd();
                let (nsk, npk) = $native::generate_derand(&seed).unwrap();
                let rsk = <ml_kem::DecapsulationKey<$rs>>::from_seed(seed.into());
                let rpk = rsk.encapsulation_key().clone();
                assert_eq!(
                    npk.0.as_slice(),
                    rpk.to_bytes().as_slice(),
                    "pk mismatch iter {i}"
                );
                assert_eq!(
                    nsk.as_bytes().as_slice(),
                    rsk.to_expanded_bytes().as_slice(),
                    "sk mismatch iter {i}"
                );

                let m: [u8; 32] = rnd();
                let (nct, nss) = npk.encapsulate_derand(&m).unwrap();
                let (rct, rss) = rpk.encapsulate_deterministic(&m.into());
                assert_eq!(nct.0.as_slice(), rct.as_slice(), "ct mismatch iter {i}");
                assert_eq!(
                    nss.as_bytes().as_slice(),
                    rss.as_slice(),
                    "ss mismatch iter {i}"
                );

                let nd = nsk.decapsulate(&nct).unwrap();
                assert_eq!(nd.as_bytes(), nss.as_bytes());

                // Implicit rejection: flip one bit, both implementations must agree
                // and must not return the honest secret.
                let mut bad = nct.clone();
                let pos = (rnd_u32() as usize) % bad.0.len();
                bad.0[pos] ^= 1u8 << (rnd_u32() % 8);
                let nrej = nsk.decapsulate(&bad).unwrap();
                let rbad: $rsct = bad.0.as_slice().try_into().unwrap();
                let rrej = rsk.decapsulate(&rbad);
                assert_eq!(
                    nrej.as_bytes().as_slice(),
                    rrej.as_slice(),
                    "implicit rejection mismatch iter {i}"
                );
                assert_ne!(nrej.as_bytes(), nss.as_bytes());

                // Randomized path: native encaps, RustCrypto decaps.
                let (ct2, ss2) = npk.encapsulate().unwrap();
                let rct2: $rsct = ct2.0.as_slice().try_into().unwrap();
                assert_eq!(rsk.decapsulate(&rct2).as_slice(), ss2.as_bytes().as_slice());
            }
            // FIPS 203 modulus check on ek: set first 12-bit coefficient to 0xFFF (>= q).
            let (sk, pk) = $native::generate().unwrap();
            let mut badpk = pk.clone();
            badpk.0[0] = 0xFF;
            badpk.0[1] |= 0x0F;
            assert_eq!(badpk.encapsulate().err(), Some(Error::InvalidInput));
            // FIPS 203 hash check on dk: corrupt H(ek) inside dk.
            let mut skb = sk.as_bytes().to_vec();
            let h_off = $native::SECRET_KEY_BYTES - 64;
            skb[h_off] ^= 1;
            let badsk = $native::DecapsulationKey::from_bytes(&skb).unwrap();
            let (ct, _) = pk.encapsulate().unwrap();
            assert_eq!(badsk.decapsulate(&ct).err(), Some(Error::InvalidInput));
            assert!($native::EncapsulationKey::from_bytes(&[0u8; 10]).is_err());
        }
    };
}
kem_diff!(
    mlkem768_matches_rustcrypto,
    mlkem768,
    ml_kem::MlKem768,
    ml_kem::ml_kem_768::Ciphertext
);
kem_diff!(
    mlkem1024_matches_rustcrypto,
    mlkem1024,
    ml_kem::MlKem1024,
    ml_kem::ml_kem_1024::Ciphertext
);

#[test]
fn mldsa65_matches_rustcrypto() {
    use ml_dsa::{EncodedVerifyingKey, Keypair as _, MlDsa65, Signature, VerifyingKey};
    for i in 0..iters() {
        let seed: [u8; 32] = rnd();
        let (nsk, npk) = mldsa65::generate_from_seed(&seed).unwrap();
        let rkp = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed.into());
        let rvk = rkp.verifying_key();
        assert_eq!(
            npk.0.as_slice(),
            rvk.encode().as_slice(),
            "pk mismatch iter {i}"
        );
        assert_eq!(
            nsk.as_bytes().as_slice(),
            rkp.expanded_key().to_expanded().as_slice(),
            "sk mismatch iter {i}"
        );

        let mlen = (rnd_u32() % 512) as usize;
        let mut msg = vec![0u8; mlen];
        getrandom::fill(&mut msg).unwrap();
        let clen = (rnd_u32() % 256) as usize;
        let mut ctx = vec![0u8; clen];
        getrandom::fill(&mut ctx).unwrap();

        let nsig = nsk.sign_deterministic(&msg, &ctx).unwrap();
        let rsig = rkp.expanded_key().sign_deterministic(&msg, &ctx).unwrap();
        assert_eq!(
            nsig.0.as_slice(),
            rsig.encode().as_slice(),
            "deterministic signature mismatch iter {i}"
        );

        // Hedged native signature must verify under RustCrypto and native.
        let hs = nsk.sign(&msg, &ctx).unwrap();
        let rvk2 = VerifyingKey::<MlDsa65>::decode(
            &EncodedVerifyingKey::<MlDsa65>::try_from(npk.0.as_slice()).unwrap(),
        );
        let rhs = Signature::<MlDsa65>::decode(&hs.0.as_slice().try_into().unwrap()).unwrap();
        assert!(rvk2.verify_with_context(&msg, &ctx, &rhs));
        assert!(npk.verify(&msg, &ctx, &hs.0).is_ok());

        // Negative: tampered signature, message, context.
        let mut bad = hs.clone();
        let pos = (rnd_u32() as usize) % bad.0.len();
        bad.0[pos] ^= 1u8 << (rnd_u32() % 8);
        let n_ok = npk.verify(&msg, &ctx, &bad.0).is_ok();
        let r_ok = Signature::<MlDsa65>::decode(&bad.0.as_slice().try_into().unwrap())
            .map(|s| rvk2.verify_with_context(&msg, &ctx, &s))
            .unwrap_or(false);
        assert_eq!(n_ok, r_ok, "tampered-signature verdict mismatch iter {i}");
        assert!(!n_ok);
        let mut msg2 = msg.clone();
        msg2.push(1);
        assert!(npk.verify(&msg2, &ctx, &hs.0).is_err());
        if !ctx.is_empty() {
            assert!(npk.verify(&msg, &ctx[1..], &hs.0).is_err());
        }
    }
    let (sk, pk) = mldsa65::generate().unwrap();
    assert_eq!(sk.sign(b"m", &[0u8; 256]).err(), Some(Error::InvalidInput));
    assert!(pk.verify(b"m", b"", &[0u8; 10]).is_err());
}

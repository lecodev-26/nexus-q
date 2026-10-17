//! ML-KEM-1024 + X25519 hybrid key encapsulation.
#[cfg(not(feature = "native-backend"))]
use ml_kem::FromSeed as _;
#[cfg(not(feature = "native-backend"))]
use ml_kem::KeyExport;
#[cfg(not(feature = "native-backend"))]
use ml_kem::MlKem1024;
#[cfg(not(feature = "native-backend"))]
use ml_kem::kem::{Decapsulate as _, Encapsulate as _};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024};
use sha3::{Digest, Sha3_256};
#[cfg(not(feature = "native-backend"))]
use x25519_dalek::EphemeralSecret;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

use super::kem::{KemError, SHARED_SECRET_LEN};

/// Combined public key length.
pub const PUBLIC_KEY_LEN: usize = 1600;
/// Combined ciphertext length.
pub const CIPHERTEXT_LEN: usize = 1600;
/// Serialized secret key length (64-byte ML-KEM seed + 32-byte X25519 secret).
pub const SECRET_KEY_LEN: usize = 96;
const INFO: &[u8] = b"nexusq-hybrid-kem-1024-v2";

/// A versioned NEXUS-Q-specific ML-KEM-1024/X25519 hybrid key pair.
/// This is not the X-Wing construction.
pub struct KeyPair {
    /// ML-KEM secret key (RustCrypto). Kept public for source compatibility
    /// across `native-backend` feature configurations.
    pub ml_kem_secret: DecapsulationKey1024,
    /// ML-KEM public key (RustCrypto). Kept public for source compatibility
    /// across `native-backend` feature configurations.
    pub ml_kem_public: EncapsulationKey1024,
    /// X25519 secret key.
    pub x25519_secret: StaticSecret,
    /// Cached X25519 public key (derived once from `x25519_secret`).
    x25519_public: X25519Public,
    // Preserve the FIPS 203 (d || z) seed so serialized keys remain stable
    // even when the native backend only exposes the expanded decapsulation key.
    seed: Zeroizing<[u8; 64]>,
    /// Keep the native expanded key so decapsulation does not re-encode and
    /// re-parse secret material for every operation.
    #[cfg(feature = "native-backend")]
    native_ml_kem_secret: nexusq_native_backend::mlkem1024::DecapsulationKey,
    /// Cached native public key so prepared encapsulation avoids from_bytes.
    #[cfg(feature = "native-backend")]
    native_ml_kem_public: nexusq_native_backend::mlkem1024::EncapsulationKey,
    /// Prepared AWS-LC X25519 private key. Decapsulation uses the same
    /// assembly X25519 as encapsulation and the AWS-LC comparator, instead of
    /// the pure-Rust x25519-dalek scalar multiplication.
    #[cfg(feature = "native-backend")]
    aws_x25519_secret: aws_lc_rs::agreement::PrivateKey,
}

impl KeyPair {
    /// Serialize the public half.
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_KEY_LEN);
        #[cfg(feature = "native-backend")]
        {
            out.extend_from_slice(&self.native_ml_kem_public.0);
        }
        #[cfg(not(feature = "native-backend"))]
        {
            out.extend_from_slice(&self.ml_kem_public.to_bytes());
        }
        out.extend_from_slice(self.x25519_public.as_bytes());
        out
    }

    /// Prepare the public half once for repeated encapsulations. The returned
    /// object contains public material only and can be used by a sender without
    /// retaining the recipient's private key.
    pub fn prepare_public_key(&self) -> Result<PreparedPublicKey, KemError> {
        PreparedPublicKey::from_bytes(&self.public_key_bytes())
    }

    /// Serialize the secret half.
    #[must_use]
    pub fn secret_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        let x_bytes = Zeroizing::new(self.x25519_secret.to_bytes());
        let mut out = Zeroizing::new(Vec::with_capacity(SECRET_KEY_LEN));
        out.extend_from_slice(self.seed.as_slice());
        out.extend_from_slice(x_bytes.as_ref());
        out
    }
}

/// Reusable, public-only ML-KEM-1024/X25519 recipient key material.
/// It deliberately contains no secret key, so senders need not hold recipient secrets.
pub struct PreparedPublicKey {
    #[cfg(feature = "native-backend")]
    native_ml_kem_public: nexusq_native_backend::mlkem1024::EncapsulationKey,
    #[cfg(not(feature = "native-backend"))]
    ml_kem_public: EncapsulationKey1024,
    x25519_public: X25519Public,
}

impl PreparedPublicKey {
    /// Parse the serialized hybrid public key once before reuse. The backend
    /// retains its normal per-operation validity checks for the ML-KEM key.
    pub fn from_bytes(public_key: &[u8]) -> Result<Self, KemError> {
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(KemError::InvalidPublicKey);
        }
        let (ml_pk, x_pk) = public_key.split_at(1568);
        let ml_pk_bytes: [u8; 1568] = ml_pk.try_into().map_err(|_| KemError::InvalidPublicKey)?;
        let x_pk_bytes: [u8; 32] = x_pk.try_into().map_err(|_| KemError::InvalidPublicKey)?;
        #[cfg(feature = "native-backend")]
        let native_ml_kem_public =
            nexusq_native_backend::mlkem1024::EncapsulationKey::from_bytes(&ml_pk_bytes)
                .map_err(|_| KemError::InvalidPublicKey)?;
        #[cfg(not(feature = "native-backend"))]
        let ml_kem_public = {
            let key = ml_kem::Key::<EncapsulationKey1024>::from(ml_pk_bytes);
            EncapsulationKey1024::new(&key).map_err(|_| KemError::InvalidPublicKey)?
        };
        Ok(Self {
            #[cfg(feature = "native-backend")]
            native_ml_kem_public,
            #[cfg(not(feature = "native-backend"))]
            ml_kem_public,
            x25519_public: X25519Public::from(x_pk_bytes),
        })
    }

    /// Encapsulate using the prepared public key. Wire format and shared secret
    /// are identical to [`encapsulate`].
    pub fn encapsulate_prepared(
        &self,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LEN]>), KemError> {
        let mut ct = [0u8; CIPHERTEXT_LEN];
        let mut ss = [0u8; SHARED_SECRET_LEN];
        self.encapsulate_prepared_into(&mut ct, &mut ss)?;
        Ok((ct.to_vec(), Zeroizing::new(ss)))
    }

    /// Encapsulate into caller-provided buffers; no output allocation is needed.
    pub fn encapsulate_prepared_into(
        &self,
        ciphertext_out: &mut [u8; CIPHERTEXT_LEN],
        shared_secret_out: &mut [u8; SHARED_SECRET_LEN],
    ) -> Result<(), KemError> {
        #[cfg(feature = "native-backend")]
        let ml_ss_bytes = {
            let (ct, ss) = self
                .native_ml_kem_public
                .encapsulate()
                .map_err(|_| KemError::Encapsulate)?;
            ciphertext_out[..1568].copy_from_slice(&ct.0);
            *ss.as_bytes()
        };
        #[cfg(not(feature = "native-backend"))]
        let ml_ss_bytes = {
            let (ct, ss) = self.ml_kem_public.encapsulate();
            ciphertext_out[..1568].copy_from_slice(ct.as_slice());
            <[u8; 32]>::from(ss)
        };
        let (eph_pub_bytes, x_ss_bytes) = hybrid_x25519_ephemeral(self.x25519_public.as_bytes());
        ciphertext_out[1568..].copy_from_slice(&eph_pub_bytes);
        // One-shot transcript hash on a stack buffer (same layout as AWS-LC).
        let mut transcript = [0u8; 32 + 32 + 32 + 32 + INFO.len()];
        transcript[0..32].copy_from_slice(&ml_ss_bytes);
        transcript[32..64].copy_from_slice(&x_ss_bytes);
        transcript[64..96].copy_from_slice(&eph_pub_bytes);
        transcript[96..128].copy_from_slice(self.x25519_public.as_bytes());
        transcript[128..].copy_from_slice(INFO);
        let digest = Sha3_256::digest(transcript);
        shared_secret_out.copy_from_slice(&digest);
        Ok(())
    }
}

/// Ephemeral X25519: (ephemeral_public, shared_secret).
/// Under `native-backend`, prefer ring's assembly-backed X25519 to match AWS-LC.
#[inline]
fn hybrid_x25519_ephemeral(peer_public: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    #[cfg(feature = "native-backend")]
    {
        // Use the same X25519 implementation family as the AWS-LC hybrid comparator
        // (aws-lc-rs wraps AWS-LC assembly), so the hybrid overhead is apples-to-apples.
        use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
        use aws_lc_rs::rand::SystemRandom;
        let rng = SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&X25519, &rng).expect("X25519 keygen");
        let public = private.compute_public_key().expect("X25519 public");
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(public.as_ref());
        let peer = UnparsedPublicKey::new(&X25519, peer_public.as_ref());
        let ss = agreement::agree_ephemeral(
            private,
            peer,
            aws_lc_rs::error::Unspecified,
            |key_material| {
                let mut out = [0u8; 32];
                out.copy_from_slice(key_material);
                Ok(out)
            },
        )
        .expect("X25519 agree");
        (eph_pub, ss)
    }
    #[cfg(not(feature = "native-backend"))]
    {
        let eph = EphemeralSecret::random();
        let eph_pub = X25519Public::from(&eph);
        let x_ss = eph.diffie_hellman(&X25519Public::from(*peer_public));
        (*eph_pub.as_bytes(), *x_ss.as_bytes())
    }
}

/// Generate a fresh key pair.
#[must_use]
pub fn generate() -> KeyPair {
    // One CSPRNG draw for (d||z) and the X25519 scalar (matches AWS-LC hybrid
    // keygen cost model more closely than two independent RNG calls).
    let mut seed_material = Zeroizing::new([0u8; 96]);
    getrandom::fill(seed_material.as_mut()).expect("OS RNG failed");
    let mut seed = Zeroizing::new([0u8; 64]);
    seed.copy_from_slice(&seed_material[..64]);
    let x_seed: [u8; 32] = seed_material[64..].try_into().expect("32 bytes");
    let x25519_secret = StaticSecret::from(x_seed);
    // Under native-backend the X25519 public key is derived once by AWS-LC
    // (assembly) and the prepared private key is kept for decapsulation. This
    // replaces the dalek base-point multiplication, so keygen does not pay twice.
    #[cfg(feature = "native-backend")]
    let (aws_x25519_secret, x25519_public) = {
        use aws_lc_rs::agreement::{PrivateKey, X25519};
        let sk = PrivateKey::from_private_key(&X25519, &x_seed).expect("X25519 private key");
        let pk = sk.compute_public_key().expect("X25519 public key");
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(pk.as_ref());
        (sk, X25519Public::from(pub_bytes))
    };
    #[cfg(not(feature = "native-backend"))]
    let x25519_public = X25519Public::from(&x25519_secret);
    #[cfg(feature = "native-backend")]
    let (native_ml_kem_secret, native_ml_kem_public, ml_kem_secret, ml_kem_public) = {
        let (native_secret, native_public) =
            nexusq_native_backend::mlkem1024::generate_derand(&seed)
                .expect("native ML-KEM-1024 key generation failed");
        // These public RustCrypto fields are part of the existing API. Build
        // them from trusted generated bytes without repeating input validation.
        #[allow(deprecated)]
        let expanded: ml_kem::ml_kem_1024::ExpandedDecapsulationKey = native_secret
            .as_bytes()
            .as_slice()
            .try_into()
            .expect("native ML-KEM-1024 expanded key has the specified length");
        let (rust_secret, rust_public) =
            DecapsulationKey1024::from_generated_expanded_bytes_with_public(&expanded);
        (native_secret, native_public, rust_secret, rust_public)
    };
    #[cfg(not(feature = "native-backend"))]
    let (ml_kem_secret, ml_kem_public) = MlKem1024::from_seed(&(*seed).into());
    KeyPair {
        ml_kem_secret,
        ml_kem_public,
        x25519_secret,
        x25519_public,
        seed,
        #[cfg(feature = "native-backend")]
        native_ml_kem_secret,
        #[cfg(feature = "native-backend")]
        native_ml_kem_public,
        #[cfg(feature = "native-backend")]
        aws_x25519_secret,
    }
}

/// Encapsulate to a serialized hybrid public key.
pub fn encapsulate(
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LEN]>), KemError> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(KemError::InvalidPublicKey);
    }
    let (ml_pk, x_pk) = public_key.split_at(1568);
    let arr: [u8; 1568] = ml_pk.try_into().map_err(|_| KemError::InvalidPublicKey)?;
    #[cfg(feature = "native-backend")]
    let (ct_bytes, ml_ss_bytes) = {
        let ml_pk = nexusq_native_backend::mlkem1024::EncapsulationKey::from_bytes(&arr)
            .map_err(|_| KemError::InvalidPublicKey)?;
        let (ct, ss) = ml_pk.encapsulate().map_err(|_| KemError::Encapsulate)?;
        (ct.0.to_vec(), *ss.as_bytes())
    };
    #[cfg(not(feature = "native-backend"))]
    let (ct_bytes, ml_ss_bytes) = {
        let key = ml_kem::Key::<EncapsulationKey1024>::from(arr);
        let ml_pk = EncapsulationKey1024::new(&key).map_err(|_| KemError::InvalidPublicKey)?;
        let (ct, ss) = ml_pk.encapsulate();
        (ct.as_slice().to_vec(), <[u8; 32]>::from(ss))
    };
    let x_arr: [u8; 32] = x_pk.try_into().map_err(|_| KemError::InvalidPublicKey)?;
    let (eph_pub_bytes, x_ss_bytes) = hybrid_x25519_ephemeral(&x_arr);
    let mut transcript = [0u8; 32 + 32 + 32 + 32 + INFO.len()];
    transcript[0..32].copy_from_slice(&ml_ss_bytes);
    transcript[32..64].copy_from_slice(&x_ss_bytes);
    transcript[64..96].copy_from_slice(&eph_pub_bytes);
    transcript[96..128].copy_from_slice(x_pk);
    transcript[128..].copy_from_slice(INFO);
    let digest = Sha3_256::digest(transcript);
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    out.copy_from_slice(&digest);
    let mut out_ct = Vec::with_capacity(CIPHERTEXT_LEN);
    out_ct.extend_from_slice(&ct_bytes);
    out_ct.extend_from_slice(&eph_pub_bytes);
    Ok((out_ct, out))
}

/// Decapsulate a serialized hybrid ciphertext.
pub fn decapsulate(
    pair: &KeyPair,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>, KemError> {
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    decapsulate_into(pair, ciphertext, &mut out)?;
    Ok(out)
}

/// Decapsulate into a caller-provided buffer (AWS-LC prepared-context model).
///
/// Avoids allocating `Zeroizing` on the timed production path; the caller owns
/// the output buffer lifetime, matching the AWS-LC hybrid comparator.
pub fn decapsulate_into(
    pair: &KeyPair,
    ciphertext: &[u8],
    shared_secret_out: &mut [u8; SHARED_SECRET_LEN],
) -> Result<(), KemError> {
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(KemError::InvalidCiphertext);
    }
    let (ml_ct, x_pub) = ciphertext.split_at(1568);
    let ct_arr: [u8; 1568] = ml_ct.try_into().map_err(|_| KemError::InvalidCiphertext)?;
    #[cfg(feature = "native-backend")]
    let ml_ss_bytes = {
        let native_ct = nexusq_native_backend::mlkem1024::Ciphertext(ct_arr);
        let ss = pair
            .native_ml_kem_secret
            .decapsulate(&native_ct)
            .map_err(|_| KemError::Decapsulate)?;
        *ss.as_bytes()
    };
    #[cfg(not(feature = "native-backend"))]
    let ml_ss_bytes = {
        let ct: ml_kem::ml_kem_1024::Ciphertext = ct_arr.into();
        let ss = pair.ml_kem_secret.decapsulate(&ct);
        <[u8; 32]>::from(ss)
    };
    let x_arr: [u8; 32] = x_pub.try_into().map_err(|_| KemError::InvalidCiphertext)?;
    #[cfg(feature = "native-backend")]
    let x_ss_bytes: [u8; 32] = {
        use aws_lc_rs::agreement::{UnparsedPublicKey, X25519, agree};
        let peer = UnparsedPublicKey::new(&X25519, x_pub);
        agree(&pair.aws_x25519_secret, peer, (), |key_material| {
            let mut out = [0u8; 32];
            out.copy_from_slice(key_material);
            Ok(out)
        })
        // AWS-LC rejects low-order peer points; keep the previous dalek
        // semantics (all-zero shared secret) so behaviour is unchanged.
        .unwrap_or_else(|()| {
            *pair
                .x25519_secret
                .diffie_hellman(&X25519Public::from(x_arr))
                .as_bytes()
        })
    };
    #[cfg(not(feature = "native-backend"))]
    let x_ss_bytes: [u8; 32] = *pair
        .x25519_secret
        .diffie_hellman(&X25519Public::from(x_arr))
        .as_bytes();
    let mut transcript = [0u8; 32 + 32 + 32 + 32 + INFO.len()];
    transcript[0..32].copy_from_slice(&ml_ss_bytes);
    transcript[32..64].copy_from_slice(&x_ss_bytes);
    transcript[64..96].copy_from_slice(x_pub);
    transcript[96..128].copy_from_slice(pair.x25519_public.as_bytes());
    transcript[128..].copy_from_slice(INFO);
    let digest = Sha3_256::digest(transcript);
    shared_secret_out.copy_from_slice(&digest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "native-backend")]
    use x25519_dalek::EphemeralSecret;

    #[test]
    fn key_material_sizes() {
        let pair = generate();
        assert_eq!(pair.public_key_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(pair.secret_key_bytes().len(), SECRET_KEY_LEN);
    }

    #[test]
    fn prepared_matches_serialized_encaps() {
        let pair = generate();
        let (ct_ser, ss_ser) = encapsulate(&pair.public_key_bytes()).unwrap();
        let prepared_public = pair.prepare_public_key().unwrap();
        let (ct_prep, ss_prep) = prepared_public.encapsulate_prepared().unwrap();
        // Different ephemeral keys => different ciphertexts and secrets, but
        // both must round-trip against the same recipient key.
        let rec_ser = decapsulate(&pair, &ct_ser).unwrap();
        let rec_prep = decapsulate(&pair, &ct_prep).unwrap();
        assert_eq!(*ss_ser, *rec_ser);
        assert_eq!(*ss_prep, *rec_prep);
    }

    #[cfg(feature = "native-backend")]
    #[test]
    fn native_ml_kem_1024_interoperates_with_rustcrypto() {
        use ml_kem::kem::{Decapsulate as _, Encapsulate as _};

        let pair = generate();
        let public_key = pair.public_key_bytes();
        let recipient_x = &public_key[1568..];

        // Native encapsulation, RustCrypto decapsulation, same hybrid transcript.
        let (native_ciphertext, native_secret) = encapsulate(&public_key).unwrap();
        let native_ml_ct: [u8; 1568] = native_ciphertext[..1568].try_into().unwrap();
        let native_ml_ct: ml_kem::ml_kem_1024::Ciphertext = native_ml_ct.into();
        let rustcrypto_ml_secret = pair.ml_kem_secret.decapsulate(&native_ml_ct);
        let eph_bytes: [u8; 32] = native_ciphertext[1568..].try_into().unwrap();
        let x_secret = pair
            .x25519_secret
            .diffie_hellman(&X25519Public::from(eph_bytes));
        let mut transcript = Zeroizing::new(Vec::new());
        transcript.extend_from_slice(rustcrypto_ml_secret.as_slice());
        transcript.extend_from_slice(x_secret.as_bytes());
        transcript.extend_from_slice(&eph_bytes);
        transcript.extend_from_slice(recipient_x);
        transcript.extend_from_slice(INFO);
        let expected = Sha3_256::digest(&transcript);
        assert_eq!(native_secret.as_slice(), expected.as_slice());

        // RustCrypto encapsulation, native decapsulation.
        let pk_bytes: [u8; 1568] = public_key[..1568].try_into().unwrap();
        let pk_array = ml_kem::Key::<EncapsulationKey1024>::from(pk_bytes);
        let rustcrypto_pk = EncapsulationKey1024::new(&pk_array).unwrap();
        let (rustcrypto_ml_ct, rustcrypto_ml_secret) = rustcrypto_pk.encapsulate();
        let eph = EphemeralSecret::random();
        let eph_public = X25519Public::from(&eph);
        let x_secret = eph.diffie_hellman(&X25519Public::from(
            <[u8; 32]>::try_from(recipient_x).unwrap(),
        ));
        let mut transcript = Zeroizing::new(Vec::new());
        transcript.extend_from_slice(rustcrypto_ml_secret.as_slice());
        transcript.extend_from_slice(x_secret.as_bytes());
        transcript.extend_from_slice(eph_public.as_bytes());
        transcript.extend_from_slice(recipient_x);
        transcript.extend_from_slice(INFO);
        let expected = Sha3_256::digest(&transcript);
        let mut ciphertext = rustcrypto_ml_ct.as_slice().to_vec();
        ciphertext.extend_from_slice(eph_public.as_bytes());
        let native_decapsulated = decapsulate(&pair, &ciphertext).unwrap();
        assert_eq!(native_decapsulated.as_slice(), expected.as_slice());
    }

    #[test]
    fn hybrid_roundtrip_and_tamper_rejection() {
        let pair = generate();
        let (ciphertext, sender_secret) = encapsulate(&pair.public_key_bytes()).unwrap();
        let receiver_secret = decapsulate(&pair, &ciphertext).unwrap();
        assert_eq!(*sender_secret, *receiver_secret);

        let mut tampered = ciphertext;
        tampered[1599] ^= 1;
        let tampered_secret = decapsulate(&pair, &tampered).unwrap();
        assert_ne!(*sender_secret, *tampered_secret);
    }
}

//! ML-KEM-1024 + X25519 hybrid key encapsulation.
#[cfg(feature = "native-backend")]
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding as _;
#[cfg(not(feature = "native-backend"))]
use ml_kem::FromSeed as _;
#[cfg(not(feature = "native-backend"))]
use ml_kem::MlKem1024;
#[cfg(not(feature = "native-backend"))]
use ml_kem::kem::Kem;
#[cfg(not(feature = "native-backend"))]
use ml_kem::kem::{Decapsulate as _, Encapsulate as _};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, KeyExport};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
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
    /// ML-KEM secret key.
    pub ml_kem_secret: DecapsulationKey1024,
    /// ML-KEM public key.
    pub ml_kem_public: EncapsulationKey1024,
    /// X25519 secret key.
    pub x25519_secret: StaticSecret,
    // Preserve the FIPS 203 (d || z) seed so serialized keys remain stable
    // even when the native backend only exposes the expanded decapsulation key.
    seed: Zeroizing<[u8; 64]>,
}

impl KeyPair {
    /// Serialize the public half.
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let x_pub = X25519Public::from(&self.x25519_secret);
        let mut out = Vec::with_capacity(PUBLIC_KEY_LEN);
        out.extend_from_slice(&self.ml_kem_public.to_bytes());
        out.extend_from_slice(x_pub.as_bytes());
        out
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

/// Generate a fresh key pair.
#[must_use]
pub fn generate() -> KeyPair {
    let mut seed = Zeroizing::new([0u8; 64]);
    getrandom::fill(seed.as_mut()).expect("OS RNG failed");
    #[cfg(feature = "native-backend")]
    let (ml_kem_secret, ml_kem_public) = {
        // Generate (d || z) once and preserve it for stable serialization.
        // The same seed drives native keygen and the RustCrypto key adapter.
        let (native_secret, native_public) =
            nexusq_native_backend::mlkem1024::generate_derand(&seed)
                .expect("native ML-KEM-1024 key generation failed");
        #[allow(deprecated)]
        let expanded: ml_kem::ml_kem_1024::ExpandedDecapsulationKey = native_secret
            .as_bytes()
            .as_slice()
            .try_into()
            .expect("native ML-KEM-1024 expanded key has the specified length");
        #[allow(deprecated)]
        let secret = DecapsulationKey1024::from_expanded_bytes(&expanded)
            .expect("native ML-KEM-1024 key must satisfy the RustCrypto key checks");
        let public_bytes: [u8; 1568] = native_public.0;
        let public_key = ml_kem::Key::<EncapsulationKey1024>::from(public_bytes);
        let public = EncapsulationKey1024::new(&public_key)
            .expect("native ML-KEM-1024 public key must satisfy the RustCrypto key checks");
        (secret, public)
    };
    #[cfg(not(feature = "native-backend"))]
    let (ml_kem_secret, ml_kem_public) = MlKem1024::from_seed(&(*seed).into());
    KeyPair {
        ml_kem_secret,
        ml_kem_public,
        x25519_secret: StaticSecret::random(),
        seed,
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
    let eph = EphemeralSecret::random();
    let eph_pub = X25519Public::from(&eph);
    let x_ss = eph.diffie_hellman(&X25519Public::from(x_arr));
    let mut input = Zeroizing::new(Vec::with_capacity(64 + 32 + 32 + INFO.len()));
    input.extend_from_slice(&ml_ss_bytes);
    input.extend_from_slice(x_ss.as_bytes());
    input.extend_from_slice(eph_pub.as_bytes());
    input.extend_from_slice(x_pk);
    input.extend_from_slice(INFO);
    let digest = Sha3_256::digest(&input);
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    out.copy_from_slice(&digest);
    // The ciphertext carries the same X25519 ephemeral public key that was
    // authenticated by the combiner above.
    let mut out_ct = Vec::with_capacity(CIPHERTEXT_LEN);
    out_ct.extend_from_slice(&ct_bytes);
    out_ct.extend_from_slice(eph_pub.as_bytes());
    Ok((out_ct, out))
}

/// Decapsulate a serialized hybrid ciphertext.
pub fn decapsulate(
    pair: &KeyPair,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>, KemError> {
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(KemError::InvalidCiphertext);
    }
    let (ml_ct, x_pub) = ciphertext.split_at(1568);
    let ct_arr: [u8; 1568] = ml_ct.try_into().map_err(|_| KemError::InvalidCiphertext)?;
    #[cfg(feature = "native-backend")]
    let ml_ss_bytes = {
        // Reuse the already-expanded FIPS key; do not repeat key generation on
        // each decapsulation. This representation is identical to the native ABI.
        #[allow(deprecated)]
        let encoded_secret = pair.ml_kem_secret.to_expanded_bytes();
        let native_bytes: Zeroizing<[u8; 3168]> = Zeroizing::new(
            encoded_secret
                .as_slice()
                .try_into()
                .expect("ML-KEM-1024 expanded secret key is 3168 bytes"),
        );
        let native_secret =
            nexusq_native_backend::mlkem1024::DecapsulationKey::from_bytes(native_bytes.as_slice())
                .map_err(|_| KemError::Decapsulate)?;
        let native_ct = nexusq_native_backend::mlkem1024::Ciphertext(ct_arr);
        let ss = native_secret
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
    let x_ss = pair
        .x25519_secret
        .diffie_hellman(&X25519Public::from(x_arr));
    let mut input = Zeroizing::new(Vec::with_capacity(64 + 32 + 32 + INFO.len()));
    input.extend_from_slice(&ml_ss_bytes);
    input.extend_from_slice(x_ss.as_bytes());
    input.extend_from_slice(x_pub);
    let recipient_pk_x = X25519Public::from(&pair.x25519_secret);
    input.extend_from_slice(recipient_pk_x.as_bytes());
    input.extend_from_slice(INFO);
    let digest = Sha3_256::digest(&input);
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    out.copy_from_slice(&digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_material_sizes() {
        let pair = generate();
        assert_eq!(pair.public_key_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(pair.secret_key_bytes().len(), SECRET_KEY_LEN);
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

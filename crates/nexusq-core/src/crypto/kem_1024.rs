//! ML-KEM-1024 + X25519 hybrid key encapsulation.
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, KeyExport, MlKem1024};
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

/// A hybrid ML-KEM-1024/X25519 key pair.
pub struct KeyPair {
    /// ML-KEM secret key.
    pub ml_kem_secret: DecapsulationKey1024,
    /// ML-KEM public key.
    pub ml_kem_public: EncapsulationKey1024,
    /// X25519 secret key.
    pub x25519_secret: StaticSecret,
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
        let seed = Zeroizing::new(
            self.ml_kem_secret
                .to_seed()
                .expect("generated ML-KEM key has a seed"),
        );
        let x_bytes = Zeroizing::new(self.x25519_secret.to_bytes());
        let mut out = Zeroizing::new(Vec::with_capacity(SECRET_KEY_LEN));
        out.extend_from_slice(seed.as_slice());
        out.extend_from_slice(x_bytes.as_ref());
        out
    }
}

/// Generate a fresh key pair.
#[must_use]
pub fn generate() -> KeyPair {
    let (ml_kem_secret, ml_kem_public) = MlKem1024::generate_keypair();
    KeyPair {
        ml_kem_secret,
        ml_kem_public,
        x25519_secret: StaticSecret::random(),
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
    let key = ml_kem::Key::<EncapsulationKey1024>::from(arr);
    let ml_pk = EncapsulationKey1024::new(&key).map_err(|_| KemError::InvalidPublicKey)?;
    let (ct, ml_ss) = ml_pk.encapsulate();
    let x_arr: [u8; 32] = x_pk.try_into().map_err(|_| KemError::InvalidPublicKey)?;
    let eph = EphemeralSecret::random();
    let eph_pub = X25519Public::from(&eph);
    let x_ss = eph.diffie_hellman(&X25519Public::from(x_arr));
    let mut input = Zeroizing::new(Vec::with_capacity(64 + 32 + 32 + INFO.len()));
    input.extend_from_slice(ml_ss.as_slice());
    input.extend_from_slice(x_ss.as_bytes());
    input.extend_from_slice(eph_pub.as_bytes());
    input.extend_from_slice(x_pk);
    input.extend_from_slice(INFO);
    let digest = Sha3_256::digest(&input);
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    out.copy_from_slice(&digest);
    // Recompute the ephemeral public key: the secret was consumed above, so use a fresh construction.
    // The public key must correspond to the shared secret; generate both together instead.
    let mut out_ct = Vec::with_capacity(CIPHERTEXT_LEN);
    out_ct.extend_from_slice(ct.as_slice());
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
    let ct: ml_kem::ml_kem_1024::Ciphertext = ct_arr.into();
    let ml_ss = pair.ml_kem_secret.decapsulate(&ct);
    let x_arr: [u8; 32] = x_pub.try_into().map_err(|_| KemError::InvalidCiphertext)?;
    let x_ss = pair
        .x25519_secret
        .diffie_hellman(&X25519Public::from(x_arr));
    let mut input = Zeroizing::new(Vec::with_capacity(64 + 32 + 32 + INFO.len()));
    input.extend_from_slice(ml_ss.as_slice());
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

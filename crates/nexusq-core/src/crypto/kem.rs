//! Key encapsulation mechanisms.
//!
//! Two constructions are exposed:
//!
//! - [`ml_kem_768`] — plain ML-KEM-768 (FIPS 203).
//! - [`hybrid`] — ML-KEM-768 combined with X25519 using the X-Wing construction. This is the
//!   default for NEXUS-Q, per `docs/CRYPTOGRAPHY.md` §4.5 and §5.3.
//!
//! The hybrid mode protects against both directions of failure: if ML-KEM
//! is broken, X25519 still holds; if X25519 is broken by a quantum
//! adversary, ML-KEM still holds.

use ml_kem::FromSeed as _;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{DecapsulationKey768, EncapsulationKey768, KeyExport, MlKem768};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

/// Length in bytes of a shared secret produced by either KEM.
pub const SHARED_SECRET_LEN: usize = 32;

/// X-Wing domain-separation label used by the SHA3-256 combiner.
const XWING_LABEL: &[u8; 6] = &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// Errors returned by the KEM module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KemError {
    /// Encapsulation failed.
    #[error("encapsulation failed")]
    Encapsulate,

    /// Decapsulation failed.
    #[error("decapsulation failed")]
    Decapsulate,

    /// The ciphertext length was wrong for the selected algorithm.
    #[error("invalid ciphertext length")]
    InvalidCiphertext,

    /// The public key length was wrong for the selected algorithm.
    #[error("invalid public key length")]
    InvalidPublicKey,

    /// The secret key length was wrong.
    #[error("invalid secret key length")]
    InvalidSecretKey,

    /// Hybrid shared-secret combination failed.
    #[error("hybrid key combination failed")]
    HybridCombine,
}

// =============================================================================
// Plain ML-KEM-768
// =============================================================================

/// Plain ML-KEM-768. Prefer [`hybrid`] for real use.
pub mod ml_kem_768 {
    use super::*;

    /// Length in bytes of an ML-KEM-768 encapsulation key (public).
    pub const PUBLIC_KEY_LEN: usize = 1184;

    /// Length in bytes of an ML-KEM-768 ciphertext.
    pub const CIPHERTEXT_LEN: usize = 1088;

    /// Generates a fresh ML-KEM-768 key pair.
    ///
    /// # Panics
    ///
    /// Panics if the OS RNG fails.
    #[must_use]
    pub fn generate() -> (DecapsulationKey768, EncapsulationKey768) {
        MlKem768::generate_keypair()
    }

    /// Serializes a public key to bytes.
    #[must_use]
    pub fn public_key_bytes(public: &EncapsulationKey768) -> Vec<u8> {
        public.to_bytes().to_vec()
    }

    /// Parses a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::InvalidPublicKey`] if the length is wrong or
    /// the key fails validation.
    pub fn public_key_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey768, KemError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(KemError::InvalidPublicKey);
        }
        let arr: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| KemError::InvalidPublicKey)?;
        let key_arr: ml_kem::Key<EncapsulationKey768> = arr.into();
        EncapsulationKey768::new(&key_arr).map_err(|_| KemError::InvalidPublicKey)
    }

    /// Encapsulates a shared secret to `public`.
    ///
    /// Returns the ciphertext and the shared secret.
    pub fn encapsulate(
        public: &EncapsulationKey768,
    ) -> (Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LEN]>) {
        let (ct, ss) = public.encapsulate();
        (ct.as_slice().to_vec(), Zeroizing::new(ss.into()))
    }

    /// Decapsulates `ciphertext` with `secret`.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::InvalidCiphertext`] if the length is wrong.
    pub fn decapsulate(
        secret: &DecapsulationKey768,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>, KemError> {
        if ciphertext.len() != CIPHERTEXT_LEN {
            return Err(KemError::InvalidCiphertext);
        }
        let arr: [u8; CIPHERTEXT_LEN] = ciphertext
            .try_into()
            .map_err(|_| KemError::InvalidCiphertext)?;
        let ct: ml_kem::ml_kem_768::Ciphertext = arr.into();
        let ss = secret.decapsulate(&ct);
        Ok(Zeroizing::new(ss.into()))
    }
}

// =============================================================================
// Hybrid ML-KEM-768 + X25519
// =============================================================================

/// Hybrid ML-KEM-768 + X25519. Default construction for NEXUS-Q.
pub mod hybrid {
    use super::*;

    /// Length in bytes of the combined public key.
    pub const PUBLIC_KEY_LEN: usize = ml_kem_768::PUBLIC_KEY_LEN + 32;

    /// Length in bytes of the combined ciphertext.
    pub const CIPHERTEXT_LEN: usize = ml_kem_768::CIPHERTEXT_LEN + 32;

    /// Length in bytes of the serialized X-Wing decapsulation key.
    pub const SECRET_KEY_LEN: usize = 32;

    /// A hybrid key pair.
    pub struct KeyPair {
        pub ml_kem_public: EncapsulationKey768,
        pub ml_kem_secret: DecapsulationKey768,
        pub x25519_secret: StaticSecret,
        seed: Zeroizing<[u8; SECRET_KEY_LEN]>,
    }

    impl KeyPair {
        #[must_use]
        pub fn secret_key_bytes(&self) -> Zeroizing<Vec<u8>> {
            Zeroizing::new(self.seed.to_vec())
        }

        #[must_use]
        pub fn public_key_bytes(&self) -> Vec<u8> {
            let x_pub = X25519Public::from(&self.x25519_secret);
            let mut out = Vec::with_capacity(PUBLIC_KEY_LEN);
            out.extend_from_slice(&ml_kem_768::public_key_bytes(&self.ml_kem_public));
            out.extend_from_slice(x_pub.as_bytes());
            out
        }
    }

    fn expand_seed(seed: &[u8; SECRET_KEY_LEN]) -> KeyPair {
        let mut expanded = Zeroizing::new([0u8; 96]);
        let mut reader = Shake256::default().chain(seed).finalize_xof();
        reader.read(expanded.as_mut());

        let ml_seed: Zeroizing<[u8; 64]> =
            Zeroizing::new(expanded[..64].try_into().expect("64-byte slice"));
        let x_seed: Zeroizing<[u8; 32]> =
            Zeroizing::new(expanded[64..].try_into().expect("32-byte slice"));
        let (ml_kem_secret, ml_kem_public) = MlKem768::from_seed(&(*ml_seed).into());
        let x25519_secret = StaticSecret::from(*x_seed);

        KeyPair {
            ml_kem_public,
            ml_kem_secret,
            x25519_secret,
            seed: Zeroizing::new(*seed),
        }
    }

    pub fn from_secret_key_bytes(bytes: &[u8]) -> Result<KeyPair, KemError> {
        if bytes.len() != SECRET_KEY_LEN {
            return Err(KemError::InvalidSecretKey);
        }
        let seed: [u8; SECRET_KEY_LEN] =
            bytes.try_into().map_err(|_| KemError::InvalidSecretKey)?;
        Ok(expand_seed(&seed))
    }

    /// Generates a hybrid key pair.
    #[must_use]
    pub fn generate() -> KeyPair {
        let mut seed = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        getrandom::fill(seed.as_mut()).expect("OS RNG failed");
        expand_seed(&seed)
    }

    /// Encapsulates a shared secret to a serialized hybrid public key.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::InvalidPublicKey`] if the length is wrong.
    pub fn encapsulate(
        public_key: &[u8],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LEN]>), KemError> {
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(KemError::InvalidPublicKey);
        }
        let (ml_pk_bytes, x_pk_bytes) = public_key.split_at(ml_kem_768::PUBLIC_KEY_LEN);

        let ml_pk = ml_kem_768::public_key_from_bytes(ml_pk_bytes)?;
        let (ml_ct, ml_ss) = ml_kem_768::encapsulate(&ml_pk);

        let x_pk_arr: [u8; 32] = x_pk_bytes
            .try_into()
            .map_err(|_| KemError::InvalidPublicKey)?;
        let x_pk = X25519Public::from(x_pk_arr);

        let eph = EphemeralSecret::random();
        let eph_pub = X25519Public::from(&eph);
        let x_ss = eph.diffie_hellman(&x_pk);

        let combined = combine_secrets(
            ml_ss.as_ref(),
            x_ss.as_bytes(),
            eph_pub.as_bytes(),
            x_pk_bytes,
        )?;

        let mut ct = Vec::with_capacity(CIPHERTEXT_LEN);
        ct.extend_from_slice(&ml_ct);
        ct.extend_from_slice(eph_pub.as_bytes());

        Ok((ct, combined))
    }

    /// Decapsulates a hybrid ciphertext with a hybrid key pair.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::InvalidCiphertext`] if the length is wrong.
    pub fn decapsulate(
        pair: &KeyPair,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>, KemError> {
        if ciphertext.len() != CIPHERTEXT_LEN {
            return Err(KemError::InvalidCiphertext);
        }
        let (ml_ct, x_pk_bytes) = ciphertext.split_at(ml_kem_768::CIPHERTEXT_LEN);

        let ml_ss = ml_kem_768::decapsulate(&pair.ml_kem_secret, ml_ct)?;

        let x_pk_arr: [u8; 32] = x_pk_bytes
            .try_into()
            .map_err(|_| KemError::InvalidCiphertext)?;
        let x_pk = X25519Public::from(x_pk_arr);
        let x_ss = pair.x25519_secret.diffie_hellman(&x_pk);

        combine_secrets(
            ml_ss.as_ref(),
            x_ss.as_bytes(),
            x_pk_bytes,
            &pair.public_key_bytes()[ml_kem_768::PUBLIC_KEY_LEN..],
        )
    }

    fn combine_secrets(
        ml_ss: &[u8],
        x_ss: &[u8],
        ct_x: &[u8],
        pk_x: &[u8],
    ) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>, KemError> {
        let mut input = Zeroizing::new(Vec::with_capacity(
            ml_ss.len() + x_ss.len() + ct_x.len() + pk_x.len() + XWING_LABEL.len(),
        ));
        input.extend_from_slice(ml_ss);
        input.extend_from_slice(x_ss);
        input.extend_from_slice(ct_x);
        input.extend_from_slice(pk_x);
        input.extend_from_slice(XWING_LABEL);

        let digest = Sha3_256::digest(&input);
        let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
        out.copy_from_slice(&digest);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_768_roundtrip() {
        let (sk, pk) = ml_kem_768::generate();
        let (ct, ss1) = ml_kem_768::encapsulate(&pk);
        assert_eq!(ct.len(), ml_kem_768::CIPHERTEXT_LEN);
        let ss2 = ml_kem_768::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn ml_kem_768_rejects_short_ciphertext() {
        let (sk, _pk) = ml_kem_768::generate();
        assert!(matches!(
            ml_kem_768::decapsulate(&sk, &[0u8; 10]),
            Err(KemError::InvalidCiphertext)
        ));
    }

    #[test]
    fn ml_kem_768_public_key_serialization_roundtrip() {
        let (_sk, pk) = ml_kem_768::generate();
        let bytes = ml_kem_768::public_key_bytes(&pk);
        assert_eq!(bytes.len(), ml_kem_768::PUBLIC_KEY_LEN);
        let parsed = ml_kem_768::public_key_from_bytes(&bytes).unwrap();
        assert_eq!(parsed.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn hybrid_roundtrip() {
        let pair = hybrid::generate();
        let pk = pair.public_key_bytes();
        assert_eq!(pk.len(), hybrid::PUBLIC_KEY_LEN);

        let (ct, ss1) = hybrid::encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), hybrid::CIPHERTEXT_LEN);

        let ss2 = hybrid::decapsulate(&pair, &ct).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn hybrid_rejects_short_public_key() {
        assert!(matches!(
            hybrid::encapsulate(&[0u8; 100]),
            Err(KemError::InvalidPublicKey)
        ));
    }

    #[test]
    fn hybrid_rejects_short_ciphertext() {
        let pair = hybrid::generate();
        assert!(matches!(
            hybrid::decapsulate(&pair, &[0u8; 100]),
            Err(KemError::InvalidCiphertext)
        ));
    }

    #[test]
    fn hybrid_secret_key_serialization_roundtrip() {
        let pair = hybrid::generate();
        let bytes = pair.secret_key_bytes();
        assert_eq!(bytes.len(), hybrid::SECRET_KEY_LEN);

        let restored = hybrid::from_secret_key_bytes(&bytes).unwrap();

        // Encapsulate to the original public key, decapsulate with the
        // restored secret, compare.
        let pk = pair.public_key_bytes();
        let (ct, ss1) = hybrid::encapsulate(&pk).unwrap();
        let ss2 = hybrid::decapsulate(&restored, &ct).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn hybrid_secret_key_rejects_wrong_length() {
        assert!(matches!(
            hybrid::from_secret_key_bytes(&[0u8; 10]),
            Err(KemError::InvalidSecretKey)
        ));
    }

    #[test]
    fn hybrid_binds_x25519_ciphertext_representation() {
        let pair = hybrid::generate();
        let pk = pair.public_key_bytes();
        let (ct, ss1) = hybrid::encapsulate(&pk).unwrap();

        // X25519 ignores the high bit of its u-coordinate. Flipping it would
        // preserve the X25519 shared secret in the old combiner. The transcript
        // binding must still change the final secret.
        let mut tampered = ct.clone();
        let x_offset = hybrid::CIPHERTEXT_LEN - 32;
        tampered[x_offset + 31] ^= 0x80;

        let ss2 = hybrid::decapsulate(&pair, &tampered).unwrap();
        assert_ne!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn hybrid_wrong_key_produces_different_secret() {
        let alice = hybrid::generate();
        let bob = hybrid::generate();
        let pk = alice.public_key_bytes();
        let (ct, ss1) = hybrid::encapsulate(&pk).unwrap();
        let ss2 = hybrid::decapsulate(&bob, &ct).unwrap();
        assert_ne!(ss1.as_ref(), ss2.as_ref());
    }
}

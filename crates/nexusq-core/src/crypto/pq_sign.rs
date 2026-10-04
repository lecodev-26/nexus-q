//! Post-quantum digital signatures used by NEXUS-Q.
//!
//! The wrappers deliberately expose fixed parameter sets so the vault format
//! has stable identifiers and sizes. ML-DSA-65 is the primary PQ signature;
//! SLH-DSA-SHAKE-128f is retained as a conservative hash-based alternative.

use ml_dsa::{
    Generate as _, KeyExport as _, KeyInit as _, Keypair as _, MlDsa65, SignatureEncoding as _,
    Signer as _, Verifier as _,
};
use slh_dsa::Shake128f;
use slh_dsa::{SigningKey as SlhSigningKey, VerifyingKey as SlhVerifyingKey};
use zeroize::Zeroizing;

/// ML-DSA-65 public key length.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// ML-DSA-65 secret seed length.
pub const ML_DSA_65_SECRET_KEY_LEN: usize = 32;
/// ML-DSA-65 signature length.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// SLH-DSA-SHAKE-128f public key length.
pub const SLH_DSA_SHAKE_128F_PUBLIC_KEY_LEN: usize = 32;
/// SLH-DSA-SHAKE-128f serialized secret key length.
pub const SLH_DSA_SHAKE_128F_SECRET_KEY_LEN: usize = 64;
/// SLH-DSA-SHAKE-128f signature length.
pub const SLH_DSA_SHAKE_128F_SIGNATURE_LEN: usize = 17088;

/// Error returned by post-quantum signature wrappers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PqSignError {
    /// A serialized key has the wrong shape or is not valid.
    #[error("invalid key encoding")]
    InvalidKey,
    /// A serialized signature has the wrong shape or is not valid.
    #[error("invalid signature encoding")]
    InvalidSignature,
    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,
}

/// ML-DSA-65 key pair.
pub struct MlDsa65KeyPair {
    signing: ml_dsa::SigningKey<MlDsa65>,
}

impl MlDsa65KeyPair {
    /// Generate a new key pair.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: ml_dsa::SigningKey::<MlDsa65>::generate(),
        }
    }

    /// Reconstruct from the 32-byte FIPS signing seed.
    pub fn from_secret_key(bytes: &[u8]) -> Result<Self, PqSignError> {
        let seed: [u8; ML_DSA_65_SECRET_KEY_LEN] =
            bytes.try_into().map_err(|_| PqSignError::InvalidKey)?;
        Ok(Self {
            signing: ml_dsa::SigningKey::<MlDsa65>::new(&seed.into()),
        })
    }

    /// Return the signing seed as zeroizing bytes.
    #[must_use]
    pub fn secret_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing.to_bytes().as_slice().to_vec())
    }

    /// Return the encoded public key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().as_slice().to_vec()
    }

    /// Sign a message.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing
            .try_sign(message)
            .expect("ML-DSA signing cannot fail")
            .to_bytes()
            .as_slice()
            .to_vec()
    }
}

/// Verify an ML-DSA-65 signature.
pub fn ml_dsa_65_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PqSignError> {
    let enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
        .map_err(|_| PqSignError::InvalidKey)?;
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
    let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature)
        .map_err(|_| PqSignError::InvalidSignature)?;
    vk.verify(message, &sig)
        .map_err(|_| PqSignError::VerificationFailed)
}

/// SLH-DSA-SHAKE-128f key pair.
pub struct SlhDsaShake128fKeyPair {
    signing: SlhSigningKey<Shake128f>,
}

impl SlhDsaShake128fKeyPair {
    /// Generate a new key pair.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0u8; 48];
        getrandom::fill(&mut seed).expect("OS RNG failed");
        Self {
            signing: SlhSigningKey::<Shake128f>::slh_keygen_internal(
                &seed[..16],
                &seed[16..32],
                &seed[32..],
            ),
        }
    }

    /// Reconstruct from the serialized FIPS private key.
    pub fn from_secret_key(bytes: &[u8]) -> Result<Self, PqSignError> {
        let signing =
            SlhSigningKey::<Shake128f>::try_from(bytes).map_err(|_| PqSignError::InvalidKey)?;
        Ok(Self { signing })
    }

    /// Return the serialized secret key as zeroizing bytes.
    #[must_use]
    pub fn secret_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing.to_bytes().as_slice().to_vec())
    }

    /// Return the encoded public key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().as_slice().to_vec()
    }

    /// Sign a message.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing
            .try_sign(message)
            .expect("SLH-DSA signing cannot fail")
            .to_bytes()
            .as_slice()
            .to_vec()
    }
}

/// Verify an SLH-DSA-SHAKE-128f signature.
pub fn slh_dsa_shake_128f_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PqSignError> {
    let vk =
        SlhVerifyingKey::<Shake128f>::try_from(public_key).map_err(|_| PqSignError::InvalidKey)?;
    let sig = slh_dsa::Signature::<Shake128f>::try_from(signature)
        .map_err(|_| PqSignError::InvalidSignature)?;
    vk.verify(message, &sig)
        .map_err(|_| PqSignError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_65_roundtrip_and_tamper_rejection() {
        let pair = MlDsa65KeyPair::generate();
        let msg = b"nexusq-ml-dsa-kat";
        let sig = pair.sign(msg);
        assert_eq!(pair.public_key().len(), ML_DSA_65_PUBLIC_KEY_LEN);
        assert_eq!(sig.len(), ML_DSA_65_SIGNATURE_LEN);
        ml_dsa_65_verify(&pair.public_key(), msg, &sig).unwrap();
        assert!(ml_dsa_65_verify(&pair.public_key(), b"tampered", &sig).is_err());
    }

    #[test]
    fn ml_dsa_65_secret_roundtrip() {
        let pair = MlDsa65KeyPair::generate();
        let restored = MlDsa65KeyPair::from_secret_key(&pair.secret_key()).unwrap();
        assert_eq!(pair.public_key(), restored.public_key());
    }

    #[test]
    fn slh_dsa_roundtrip_and_tamper_rejection() {
        let pair = SlhDsaShake128fKeyPair::generate();
        let msg = b"nexusq-slh-dsa-kat";
        let sig = pair.sign(msg);
        assert_eq!(pair.public_key().len(), SLH_DSA_SHAKE_128F_PUBLIC_KEY_LEN);
        assert_eq!(sig.len(), SLH_DSA_SHAKE_128F_SIGNATURE_LEN);
        slh_dsa_shake_128f_verify(&pair.public_key(), msg, &sig).unwrap();
        assert!(slh_dsa_shake_128f_verify(&pair.public_key(), b"tampered", &sig).is_err());
    }

    #[test]
    fn slh_dsa_secret_roundtrip() {
        let pair = SlhDsaShake128fKeyPair::generate();
        let restored = SlhDsaShake128fKeyPair::from_secret_key(&pair.secret_key()).unwrap();
        assert_eq!(pair.public_key(), restored.public_key());
    }
}

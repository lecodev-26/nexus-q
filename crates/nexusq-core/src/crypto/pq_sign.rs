//! Post-quantum digital signatures used by NEXUS-Q.
//!
//! The wrappers deliberately expose fixed parameter sets so the vault format
//! has stable identifiers and sizes. ML-DSA-65 is the primary PQ signature;
//! SLH-DSA-SHAKE-128f is retained as a conservative hash-based alternative.

#[cfg(not(feature = "native-backend"))]
use ml_dsa::MlDsa65;
#[cfg(not(feature = "native-backend"))]
use ml_dsa::{
    KeyExport as _, KeyInit as _, Keypair as _, SignatureEncoding as _, Signer as _, Verifier as _,
};
use slh_dsa::Shake128f;
#[cfg(feature = "native-backend")]
use slh_dsa::signature::{Keypair as _, Signer as _, Verifier as _};
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
    /// The operating system CSPRNG could not provide required randomness.
    #[error("operating system RNG failed")]
    Randomness,
    /// Key generation failed in the selected cryptographic backend.
    #[error("post-quantum key generation failed")]
    KeyGenerationFailed,
    /// Signing failed in the selected cryptographic backend.
    #[error("post-quantum signing failed")]
    SigningFailed,
}

/// ML-DSA-65 key pair.
pub struct MlDsa65KeyPair {
    #[cfg(not(feature = "native-backend"))]
    signing: ml_dsa::SigningKey<MlDsa65>,
    #[cfg(feature = "native-backend")]
    native_signing: nexusq_native_backend::mldsa65::SigningKey,
    #[cfg(feature = "native-backend")]
    seed: Zeroizing<[u8; ML_DSA_65_SECRET_KEY_LEN]>,
    #[cfg(feature = "native-backend")]
    public_key: Vec<u8>,
}

/// Reusable ML-DSA-65 verifier holding an encoded public key.
///
/// The RustCrypto implementation decodes the key at construction and reuses
/// the decoded verifier. The native implementation validates the encoded
/// length at construction and retains the bytes; the native backend currently
/// parses the key again on each `verify` call. The existing
/// `ml_dsa_65_verify` API remains unchanged.
pub struct MlDsa65VerifyingKey {
    #[cfg(not(feature = "native-backend"))]
    verifying: ml_dsa::VerifyingKey<MlDsa65>,
    #[cfg(feature = "native-backend")]
    public_key: Vec<u8>,
}

impl MlDsa65VerifyingKey {
    /// Validate and retain a serialized ML-DSA-65 public key.
    ///
    /// With RustCrypto this also decodes the key for reuse. With the native
    /// backend, validation currently checks the encoded length; the native
    /// verifier parses the key during each verification call.
    pub fn from_public_key(bytes: &[u8]) -> Result<Self, PqSignError> {
        #[cfg(not(feature = "native-backend"))]
        {
            let enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(bytes)
                .map_err(|_| PqSignError::InvalidKey)?;
            let verifying = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
            Ok(Self { verifying })
        }
        #[cfg(feature = "native-backend")]
        {
            let _ = nexusq_native_backend::mldsa65::VerifyingKey::from_bytes(bytes)
                .map_err(|_| PqSignError::InvalidKey)?;
            Ok(Self {
                public_key: bytes.to_vec(),
            })
        }
    }

    /// Verify a signature using the retained public key.
    ///
    /// The native backend currently reconstructs its verifying-key wrapper for
    /// each call; RustCrypto reuses the decoded verifier.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), PqSignError> {
        #[cfg(feature = "native-backend")]
        {
            let native_key =
                nexusq_native_backend::mldsa65::VerifyingKey::from_bytes(&self.public_key)
                    .map_err(|_| PqSignError::InvalidKey)?;
            if signature.len() != ML_DSA_65_SIGNATURE_LEN {
                return Err(PqSignError::InvalidSignature);
            }
            native_key
                .verify(message, &[], signature)
                .map_err(|_| PqSignError::VerificationFailed)
        }
        #[cfg(not(feature = "native-backend"))]
        {
            let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature)
                .map_err(|_| PqSignError::InvalidSignature)?;
            self.verifying
                .verify(message, &sig)
                .map_err(|_| PqSignError::VerificationFailed)
        }
    }
}

impl MlDsa65KeyPair {
    /// Generate a new key pair, returning entropy/backend failures to the caller.
    pub fn try_generate() -> Result<Self, PqSignError> {
        let mut seed = Zeroizing::new([0u8; ML_DSA_65_SECRET_KEY_LEN]);
        getrandom::fill(seed.as_mut()).map_err(|_| PqSignError::Randomness)?;
        #[cfg(feature = "native-backend")]
        {
            let (native_signing, verifying) =
                nexusq_native_backend::mldsa65::generate_from_seed(&seed).map_err(|error| {
                    match error {
                        nexusq_native_backend::Error::Rng => PqSignError::Randomness,
                        _ => PqSignError::KeyGenerationFailed,
                    }
                })?;
            Ok(Self {
                native_signing,
                seed,
                public_key: verifying.0.to_vec(),
            })
        }
        #[cfg(not(feature = "native-backend"))]
        {
            Ok(Self {
                signing: ml_dsa::SigningKey::<MlDsa65>::new(&(*seed).into()),
            })
        }
    }

    /// Generate a key pair using the legacy infallible API. Prefer [`Self::try_generate`].
    #[must_use]
    pub fn generate() -> Self {
        Self::try_generate()
            .expect("ML-DSA-65 key generation failed; use try_generate to handle errors")
    }

    /// Reconstruct from the 32-byte FIPS signing seed.
    pub fn from_secret_key(bytes: &[u8]) -> Result<Self, PqSignError> {
        let seed: Zeroizing<[u8; ML_DSA_65_SECRET_KEY_LEN]> =
            Zeroizing::new(bytes.try_into().map_err(|_| PqSignError::InvalidKey)?);
        #[cfg(feature = "native-backend")]
        {
            let (native_signing, verifying) =
                nexusq_native_backend::mldsa65::generate_from_seed(&seed)
                    .map_err(|_| PqSignError::InvalidKey)?;
            Ok(Self {
                native_signing,
                seed,
                public_key: verifying.0.to_vec(),
            })
        }
        #[cfg(not(feature = "native-backend"))]
        {
            let signing = ml_dsa::SigningKey::<MlDsa65>::new(&(*seed).into());
            Ok(Self { signing })
        }
    }

    /// Return the signing seed as zeroizing bytes.
    #[must_use]
    pub fn secret_key(&self) -> Zeroizing<Vec<u8>> {
        #[cfg(feature = "native-backend")]
        {
            Zeroizing::new(self.seed.to_vec())
        }
        #[cfg(not(feature = "native-backend"))]
        {
            Zeroizing::new(self.signing.to_bytes().as_slice().to_vec())
        }
    }

    /// Return the encoded public key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        #[cfg(feature = "native-backend")]
        {
            self.public_key.clone()
        }
        #[cfg(not(feature = "native-backend"))]
        {
            self.signing.verifying_key().to_bytes().as_slice().to_vec()
        }
    }

    /// Sign a message, returning backend failures to the caller.
    pub fn try_sign(&self, message: &[u8]) -> Result<Vec<u8>, PqSignError> {
        #[cfg(feature = "native-backend")]
        {
            self.native_signing
                .sign(message, &[])
                .map(|signature| signature.0.to_vec())
                .map_err(|error| match error {
                    nexusq_native_backend::Error::Rng => PqSignError::Randomness,
                    _ => PqSignError::SigningFailed,
                })
        }
        #[cfg(not(feature = "native-backend"))]
        {
            self.signing
                .try_sign(message)
                .map(|signature| signature.to_bytes().as_slice().to_vec())
                .map_err(|_| PqSignError::SigningFailed)
        }
    }

    /// Sign using the legacy infallible API. Prefer [`Self::try_sign`].
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.try_sign(message)
            .expect("ML-DSA-65 signing failed; use try_sign to handle errors")
    }
}

/// Verify an ML-DSA-65 signature.
pub fn ml_dsa_65_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PqSignError> {
    #[cfg(feature = "native-backend")]
    {
        let native_key = nexusq_native_backend::mldsa65::VerifyingKey::from_bytes(public_key)
            .map_err(|_| PqSignError::InvalidKey)?;
        if signature.len() != ML_DSA_65_SIGNATURE_LEN {
            return Err(PqSignError::InvalidSignature);
        }
        native_key
            .verify(message, &[], signature)
            .map_err(|_| PqSignError::VerificationFailed)
    }
    #[cfg(not(feature = "native-backend"))]
    {
        let enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
            .map_err(|_| PqSignError::InvalidKey)?;
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
        let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature)
            .map_err(|_| PqSignError::InvalidSignature)?;
        vk.verify(message, &sig)
            .map_err(|_| PqSignError::VerificationFailed)
    }
}

/// SLH-DSA-SHAKE-128f key pair.
pub struct SlhDsaShake128fKeyPair {
    signing: SlhSigningKey<Shake128f>,
}

impl SlhDsaShake128fKeyPair {
    /// Generate a new key pair, returning entropy failures to the caller.
    pub fn try_generate() -> Result<Self, PqSignError> {
        let mut seed = Zeroizing::new([0u8; 48]);
        getrandom::fill(seed.as_mut()).map_err(|_| PqSignError::Randomness)?;
        Ok(Self {
            signing: SlhSigningKey::<Shake128f>::slh_keygen_internal(
                &seed[..16],
                &seed[16..32],
                &seed[32..],
            ),
        })
    }

    /// Generate using the legacy infallible API. Prefer [`Self::try_generate`].
    #[must_use]
    pub fn generate() -> Self {
        Self::try_generate()
            .expect("SLH-DSA key generation failed; use try_generate to handle errors")
    }

    /// Reconstruct from the serialized FIPS private key.
    pub fn from_secret_key(bytes: &[u8]) -> Result<Self, PqSignError> {
        let secret = Zeroizing::new(bytes.to_vec());
        let signing = SlhSigningKey::<Shake128f>::try_from(secret.as_slice())
            .map_err(|_| PqSignError::InvalidKey)?;
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

    /// Sign a message, returning backend failures to the caller.
    pub fn try_sign(&self, message: &[u8]) -> Result<Vec<u8>, PqSignError> {
        self.signing
            .try_sign(message)
            .map(|signature| signature.to_bytes().as_slice().to_vec())
            .map_err(|_| PqSignError::SigningFailed)
    }

    /// Sign using the legacy infallible API. Prefer [`Self::try_sign`].
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.try_sign(message)
            .expect("SLH-DSA signing failed; use try_sign to handle errors")
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

    #[cfg(feature = "native-backend")]
    #[test]
    fn native_ml_dsa_signatures_interoperate_with_rustcrypto() {
        use ml_dsa::{KeyInit as _, MlDsa65, SignatureEncoding as _, Signer as _, Verifier as _};

        let pair = MlDsa65KeyPair::generate();
        let message = b"native-rustcrypto-interoperability";
        let public = pair.public_key();
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(public.as_slice()).unwrap();
        let rustcrypto_verifier = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded);

        let native_signature = pair.sign(message);
        let decoded_native =
            ml_dsa::Signature::<MlDsa65>::try_from(native_signature.as_slice()).unwrap();
        rustcrypto_verifier
            .verify(message, &decoded_native)
            .unwrap();

        let encoded_seed = pair.secret_key();
        let seed: Zeroizing<[u8; ML_DSA_65_SECRET_KEY_LEN]> =
            Zeroizing::new(encoded_seed.as_slice().try_into().unwrap());
        let rustcrypto_signing = ml_dsa::SigningKey::<MlDsa65>::new(&(*seed).into());
        let rustcrypto_signature = rustcrypto_signing
            .try_sign(message)
            .unwrap()
            .to_bytes()
            .as_slice()
            .to_vec();
        ml_dsa_65_verify(&public, message, &rustcrypto_signature).unwrap();
    }

    #[test]
    fn ml_dsa_65_secret_roundtrip() {
        let pair = MlDsa65KeyPair::generate();
        let restored = MlDsa65KeyPair::from_secret_key(&pair.secret_key()).unwrap();
        assert_eq!(pair.public_key(), restored.public_key());
    }

    #[test]
    fn ml_dsa_65_cached_verifier_roundtrip_and_reuse() {
        let pair = MlDsa65KeyPair::generate();
        let public_key = pair.public_key();
        let verifier = MlDsa65VerifyingKey::from_public_key(&public_key).unwrap();
        let sig = pair.sign(b"cached verifier");
        verifier.verify(b"cached verifier", &sig).unwrap();
        assert!(verifier.verify(b"tampered", &sig).is_err());
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

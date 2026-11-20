//! Isolated WebAssembly bridge for NEXUS-Q browser experiments.
//!
//! Browser-only bindings are compiled only for `wasm32`; native builds keep
//! the dependency graph small and run the same cryptographic round-trip tests
//! directly against the core API.

#[cfg(target_arch = "wasm32")]
mod browser;

#[cfg(target_arch = "wasm32")]
pub use browser::*;

#[cfg(test)]
mod tests {
    use nexusq_core::crypto::{
        kem::ml_kem_768,
        pq_sign::{MlDsa65KeyPair, MlDsa65VerifyingKey},
    };

    #[test]
    fn ml_dsa_sign_and_verify_round_trip() {
        let key_pair = MlDsa65KeyPair::try_generate().expect("CSPRNG available");
        let message = b"NEXUS-Q WASM proof of concept";
        let signature = key_pair.try_sign(message).expect("signing succeeds");
        let verifier = MlDsa65VerifyingKey::from_public_key(&key_pair.public_key())
            .expect("generated public key is valid");
        verifier
            .verify(message, &signature)
            .expect("signature verifies");
        assert!(verifier.verify(b"tampered message", &signature).is_err());
    }

    #[test]
    fn ml_kem_encapsulate_and_decapsulate_round_trip() {
        let (secret, public) = ml_kem_768::try_generate().expect("CSPRNG available");
        let (ciphertext, sender_secret) = ml_kem_768::encapsulate(&public);
        let receiver_secret =
            ml_kem_768::decapsulate(&secret, &ciphertext).expect("valid ciphertext decapsulates");
        assert_eq!(sender_secret.as_slice(), receiver_secret.as_slice());
    }
}

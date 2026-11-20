use js_sys::Uint8Array;
use nexusq_core::crypto::{
    kem::ml_kem_768,
    pq_sign::{MlDsa65KeyPair, MlDsa65VerifyingKey},
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn js_error(error: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

/// An ML-DSA-65 key pair whose private signing material remains in WASM memory.
#[wasm_bindgen]
pub struct WasmMlDsa65KeyPair {
    inner: MlDsa65KeyPair,
}

#[wasm_bindgen]
impl WasmMlDsa65KeyPair {
    /// Generate a fresh ML-DSA-65 key pair using the platform CSPRNG.
    pub fn generate() -> Result<WasmMlDsa65KeyPair, JsValue> {
        let inner = MlDsa65KeyPair::try_generate().map_err(js_error)?;
        Ok(Self { inner })
    }

    /// Return the encoded public key. The private key is never exported.
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(self.inner.public_key().as_slice())
    }

    /// Sign a message and return its detached ML-DSA-65 signature.
    pub fn sign(&self, message: &[u8]) -> Result<Uint8Array, JsValue> {
        let signature = self.inner.try_sign(message).map_err(js_error)?;
        Ok(Uint8Array::from(signature.as_slice()))
    }
}

/// Verify an ML-DSA-65 detached signature.
#[wasm_bindgen]
pub fn ml_dsa_65_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    MlDsa65VerifyingKey::from_public_key(public_key)
        .and_then(|key| key.verify(message, signature))
        .is_ok()
}

/// An ML-KEM-768 key pair whose decapsulation key remains in WASM memory.
#[wasm_bindgen]
pub struct WasmMlKem768KeyPair {
    // Keep the concrete secret-key type private to nexusq-core's KEM module.
    // The closure owns it for this WASM object lifetime.
    decapsulate_fn: Box<dyn Fn(&[u8]) -> Result<Zeroizing<Vec<u8>>, String>>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl WasmMlKem768KeyPair {
    /// Generate a fresh ML-KEM-768 key pair using the platform CSPRNG.
    pub fn generate() -> Result<WasmMlKem768KeyPair, JsValue> {
        let (secret_key, public_key) = ml_kem_768::try_generate().map_err(js_error)?;
        let decapsulate_fn = Box::new(move |ciphertext: &[u8]| {
            ml_kem_768::decapsulate(&secret_key, ciphertext)
                .map(|secret| Zeroizing::new(secret.to_vec()))
                .map_err(|error| error.to_string())
        });
        Ok(Self {
            decapsulate_fn,
            public_key: ml_kem_768::public_key_bytes(&public_key),
        })
    }

    /// Return the encoded ML-KEM-768 public key.
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(self.public_key.as_slice())
    }

    /// Decapsulate a ciphertext and return the shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Uint8Array, JsValue> {
        let shared_secret = (self.decapsulate_fn)(ciphertext).map_err(js_error)?;
        Ok(Uint8Array::from(shared_secret.as_slice()))
    }
}

/// Encapsulation result. The shared secret is exposed for educational
/// interoperability demonstrations and must not be logged or persisted.
#[wasm_bindgen]
pub struct WasmMlKem768Encapsulation {
    ciphertext: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmMlKem768Encapsulation {
    /// Return the ML-KEM-768 ciphertext.
    pub fn ciphertext(&self) -> Uint8Array {
        Uint8Array::from(self.ciphertext.as_slice())
    }

    /// Return the shared secret for local demonstration only.
    pub fn shared_secret(&self) -> Uint8Array {
        Uint8Array::from(self.shared_secret.as_slice())
    }
}

/// Encapsulate a fresh shared secret to an encoded ML-KEM-768 public key.
#[wasm_bindgen]
pub fn ml_kem_768_encapsulate(public_key: &[u8]) -> Result<WasmMlKem768Encapsulation, JsValue> {
    let public = ml_kem_768::public_key_from_bytes(public_key).map_err(js_error)?;
    let (ciphertext, shared_secret) = ml_kem_768::encapsulate(&public);
    Ok(WasmMlKem768Encapsulation {
        ciphertext,
        shared_secret: Zeroizing::new(shared_secret.to_vec()),
    })
}

#![cfg(feature = "softhsm-tests")]

use nexusq_hsm::Pkcs11Provider;
use nexusq_xks_proxy::{
    Pkcs11XksProvider, ProviderDecryptRequest, RequestMetadata, XksKeyProvider,
};

#[test]
fn softhsm_xks_adapter_validates_keys_and_performs_health_metadata_encrypt_decrypt() {
    let module = std::env::var("NEXUSQ_PKCS11_MODULE").expect("set PKCS#11 module");
    let pin = std::env::var("NEXUSQ_PKCS11_PIN").expect("set PKCS#11 PIN");
    let slot = std::env::var("NEXUSQ_PKCS11_SLOT_INDEX")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let provider = Pkcs11Provider::connect(module, slot, pin).expect("connect to SoftHSM");
    let suffix = std::process::id();
    let key = provider
        .generate_aes256_gcm_key(&format!("nexusq-xks-adapter-{suffix}"))
        .expect("generate external key");
    let health_key = provider
        .generate_aes256_gcm_key(&format!("nexusq-xks-health-{suffix}"))
        .expect("generate health key");
    let adapter = Pkcs11XksProvider::new(
        provider.clone(),
        [("external-key".to_owned(), key.clone())],
        health_key.clone(),
        "SoftHSM",
        "SoftHSM2",
    )
    .expect("construct XKS adapter");

    let health = adapter.health_check().expect("cached health response");
    assert_eq!(health.ekm_fleet_details[0].health_status, "ACTIVE");
    let metadata = RequestMetadata::default();
    let key_metadata = adapter
        .key_metadata("external-key", &metadata)
        .expect("key metadata");
    assert_eq!(key_metadata.key_spec, "AES_256");
    assert!(adapter.key_metadata("missing-key", &metadata).is_err());

    let plaintext = b"XKS adapter integration plaintext";
    let aad = b"kms-key-arn=arn:aws:kms:us-east-1:123456789012:key/test";
    let encrypted = adapter
        .encrypt("external-key", plaintext, aad, &metadata)
        .expect("encrypt through PKCS#11 adapter");
    let decrypted = adapter
        .decrypt(
            "external-key",
            ProviderDecryptRequest {
                ciphertext: &encrypted.ciphertext,
                initialization_vector: &encrypted.initialization_vector,
                authentication_tag: &encrypted.authentication_tag,
                ciphertext_metadata: &encrypted.ciphertext_metadata,
                additional_authenticated_data: aad,
                request_metadata: &metadata,
            },
        )
        .expect("decrypt through PKCS#11 adapter");
    assert_eq!(decrypted, plaintext);
    let rejected = adapter.decrypt(
        "external-key",
        ProviderDecryptRequest {
            ciphertext: &encrypted.ciphertext,
            initialization_vector: &encrypted.initialization_vector,
            authentication_tag: &encrypted.authentication_tag,
            ciphertext_metadata: b"unsupported",
            additional_authenticated_data: aad,
            request_metadata: &metadata,
        },
    );
    assert!(rejected.is_err());
    assert!(
        adapter
            .encrypt("missing-key", plaintext, aad, &metadata)
            .is_err()
    );

    provider
        .destroy_aes256_gcm_key(&key)
        .expect("destroy external test key");
    provider
        .destroy_aes256_gcm_key(&health_key)
        .expect("destroy health test key");
}

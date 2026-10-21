#![cfg(feature = "softhsm-tests")]

use der::Encode;
use ml_dsa::{Generate, MlDsa65, Signature as MlDsaSignature, SigningKey};
use nexusq_enrollment::{EnrollmentAuthority, EnrollmentPolicy, Principal, Protocol};
use nexusq_hsm::{Pkcs11MlDsaSigner, Pkcs11Provider};
use nexusq_x509::{MlDsa65Signer, build_certificate_with_external_ml_dsa65_signer};
use signature::Verifier;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::cabf},
    ext::pkix::{SubjectAltName, name::GeneralName},
    name::Name,
    request::RequestBuilder,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity,
};

#[test]
fn softhsm_keeps_mldsa_private_key_non_extractable_and_signs_inside_token() {
    let module = std::env::var("NEXUSQ_PKCS11_MODULE")
        .expect("set NEXUSQ_PKCS11_MODULE via scripts/test-softhsm.sh");
    let pin = std::env::var("NEXUSQ_PKCS11_PIN")
        .expect("set NEXUSQ_PKCS11_PIN via scripts/test-softhsm.sh");
    let slot = std::env::var("NEXUSQ_PKCS11_SLOT_INDEX")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let provider =
        Pkcs11Provider::connect(module, slot, pin).expect("connect to initialized SoftHSM token");
    let label = format!("nexusq-softhsm-test-{}", std::process::id());
    let key = provider
        .generate_mldsa65_ca_key(&label)
        .expect("SoftHSM must support PKCS#11 ML-DSA-65 key generation");
    assert!(
        provider
            .private_key_is_non_extractable(&key)
            .expect("read key policy attributes")
    );
    let signer = std::sync::Arc::new(
        Pkcs11MlDsaSigner::new(provider.clone(), key.clone()).expect("parse public key"),
    );
    let message = b"NexusQ PKCS#11 HSM signing integration test";
    let signature = signer.sign(message).expect("sign inside token");
    let signature = MlDsaSignature::<MlDsa65>::try_from(signature.as_slice())
        .expect("valid ML-DSA signature encoding");
    signer
        .verifying_key()
        .verify(message, &signature)
        .expect("verify signature against public key");

    let ca_name = Name::from_str("CN=NexusQ HSM Test Root,O=NexusQ,C=US").unwrap();
    let profile = cabf::Root::new(false, ca_name).unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(&signer.public_key()).unwrap();
    let builder = CertificateBuilder::new(
        profile,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60)).unwrap(),
        spki,
    )
    .unwrap();
    let ca_certificate =
        build_certificate_with_external_ml_dsa65_signer(builder, signer.public_key(), |tbs| {
            signer.sign(tbs)
        })
        .unwrap();
    let authority = EnrollmentAuthority::new_with_signer(
        ca_certificate,
        signer.clone(),
        EnrollmentPolicy::new(vec!["example.com".to_owned()]).unwrap(),
        2,
    )
    .unwrap();
    let csr_key = SigningKey::<MlDsa65>::generate();
    let subject = Name::from_str("CN=hsm.example.com").unwrap();
    let mut csr_builder = RequestBuilder::new(subject).unwrap();
    csr_builder
        .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
            der::asn1::Ia5String::new("hsm.example.com").unwrap(),
        )]))
        .unwrap();
    let csr = csr_builder
        .build::<SigningKey<MlDsa65>, MlDsaSignature<MlDsa65>>(&csr_key)
        .unwrap();
    let leaf = authority
        .enroll_csr(
            &Principal {
                id: "softhsm-test".to_owned(),
            },
            Protocol::Est,
            &csr.to_der().unwrap(),
        )
        .unwrap();
    let leaf_signature =
        MlDsaSignature::<MlDsa65>::try_from(leaf.signature().as_bytes().unwrap()).unwrap();
    signer
        .verifying_key()
        .verify(&leaf.tbs_certificate().to_der().unwrap(), &leaf_signature)
        .expect("certificate was signed by the HSM key");
    provider
        .destroy_key(&key)
        .expect("remove temporary integration-test key");
}

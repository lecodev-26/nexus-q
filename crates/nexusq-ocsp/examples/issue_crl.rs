use std::{
    str::FromStr,
    time::{Duration, SystemTime},
};

use der::{Decode, EncodePem};
use ml_dsa::{Generate, Keypair, MlDsa65, SigningKey};
use nexusq_ocsp::{RevocationStore, build_ml_dsa65_crl};
use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::cabf},
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/nexusq-ocsp-crl-smoke".to_owned());
    std::fs::create_dir_all(&out)?;
    let signer = SigningKey::<MlDsa65>::generate();
    let subject = Name::from_str("CN=NexusQ OCSP Interop Root,O=NexusQ,C=US")?;
    let profile = cabf::Root::new(false, subject)?;
    let spki = SubjectPublicKeyInfoOwned::from_key(&signer.verifying_key())?;
    let builder = CertificateBuilder::new(
        profile,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(86400))?,
        spki,
    )?;
    let cert = builder.build::<SigningKey<MlDsa65>, ml_dsa::Signature<MlDsa65>>(&signer)?;
    let cert_pem = cert.to_pem(der::pem::LineEnding::LF)?;
    std::fs::write(format!("{out}/issuer.pem"), cert_pem)?;
    let mut store = RevocationStore::new();
    store.revoke(
        &SerialNumber::from(77u32),
        SystemTime::now(),
        Some(x509_cert::ext::pkix::crl::CrlReason::KeyCompromise),
    )?;
    let crl = build_ml_dsa65_crl(cert.tbs_certificate().subject(), &signer, &store, 1)?;
    // Verify the returned bytes decode as an X.509 CertificateList before writing them.
    let _: x509_cert::crl::CertificateList = x509_cert::crl::CertificateList::from_der(&crl)?;
    std::fs::write(format!("{out}/revoked.crl.der"), crl)?;
    println!("Wrote test issuer certificate and DER CRL to {out}; no private key was exported.");
    Ok(())
}

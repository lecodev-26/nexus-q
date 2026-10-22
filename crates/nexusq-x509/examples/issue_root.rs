use core::{str::FromStr, time::Duration};

use ml_dsa::{Generate, MlDsa65, SigningKey};
use nexusq_x509::{certificate_to_pem, issue_self_signed_ml_dsa65_root, validity_for};
use x509_cert::{name::Name, serial_number::SerialNumber};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nexusq-root.pem".to_owned());
    let signer = SigningKey::<MlDsa65>::generate();
    let subject = Name::from_str("CN=NexusQ Root,O=NexusQ,C=US")?;
    let certificate = issue_self_signed_ml_dsa65_root(
        subject,
        SerialNumber::from(1u32),
        validity_for(Duration::from_secs(365 * 24 * 60 * 60))?,
        &signer,
    )?;
    std::fs::write(&output, certificate_to_pem(&certificate)?)?;
    println!("Wrote self-signed ML-DSA-65 root certificate to {output}");
    println!("The private key was generated in memory and was not exported.");
    Ok(())
}

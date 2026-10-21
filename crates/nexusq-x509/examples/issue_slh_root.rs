use core::{str::FromStr, time::Duration};

use nexusq_x509::{certificate_to_pem, issue_self_signed_slh_dsa_root, validity_for};
use slh_dsa::{Shake128f, SigningKey};
use x509_cert::{name::Name, serial_number::SerialNumber};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nexusq-slh-root.pem".to_owned());
    let mut rng = rand::rng();
    let signer = SigningKey::<Shake128f>::new(&mut rng);
    let subject = Name::from_str("CN=NexusQ SLH-DSA Root,O=NexusQ,C=US")?;
    let certificate = issue_self_signed_slh_dsa_root(
        subject,
        SerialNumber::from(2u32),
        validity_for(Duration::from_secs(365 * 24 * 60 * 60))?,
        &signer,
    )?;
    std::fs::write(&output, certificate_to_pem(&certificate)?)?;
    println!("Wrote self-signed SLH-DSA root certificate to {output}");
    println!("The private key was generated in memory and was not exported.");
    Ok(())
}

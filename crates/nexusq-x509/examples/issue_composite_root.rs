use core::{str::FromStr, time::Duration};

use nexusq_x509::{
    certificate_to_pem,
    composite::{CompositeSigningKey, issue_composite_root_for},
};
use x509_cert::{name::Name, serial_number::SerialNumber};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nexusq-composite-root.pem".to_owned());
    let signer = CompositeSigningKey::generate();
    let subject = Name::from_str("CN=NexusQ Composite Root,O=NexusQ,C=US")?;
    let certificate = issue_composite_root_for(
        subject,
        SerialNumber::from(3u32),
        Duration::from_secs(365 * 24 * 60 * 60),
        &signer,
    )?;
    std::fs::write(&output, certificate_to_pem(&certificate)?)?;
    println!("Wrote experimental draft composite ML-DSA-65 + Ed25519 root to {output}");
    println!("The component private keys were generated in memory and were not exported.");
    Ok(())
}

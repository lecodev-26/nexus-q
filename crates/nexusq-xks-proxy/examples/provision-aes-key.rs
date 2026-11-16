use std::env;

use nexusq_hsm::Pkcs11Provider;
use zeroize::Zeroizing;

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::NotFound, format!("{name} is required")).into()
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = required("NEXUSQ_PKCS11_MODULE")?;
    let slot: usize = required("NEXUSQ_PKCS11_SLOT_INDEX")?.parse()?;
    let mut pin = Zeroizing::new(required("NEXUSQ_PKCS11_PIN")?);
    let label = required("NEXUSQ_XKS_KEY_LABEL")?;
    let external_key_id = required("NEXUSQ_XKS_EXTERNAL_KEY_ID")?;

    let provider = Pkcs11Provider::connect(&module, slot, std::mem::take(&mut *pin))?;
    let key_ref = provider.generate_aes256_gcm_key(&label)?;
    if !provider.aes256_key_is_protected(&key_ref)? {
        let _ = provider.destroy_aes256_gcm_key(&key_ref);
        return Err(std::io::Error::other(
            "HSM did not preserve the required non-extractable AES-256 policy",
        )
        .into());
    }

    let mapping = serde_json::json!({
        "externalKeyId": external_key_id,
        "keyRef": key_ref,
    });
    println!("{}", serde_json::to_string_pretty(&mapping)?);
    Ok(())
}

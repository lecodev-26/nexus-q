#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::identity::Credential;

fuzz_target!(|data: &[u8]| {
    let _ = nexusq_core::vault::from_slice::<Credential>(data);
    let _ = Credential::verify_with_public_key(data, &[0u8; 32]);
    let _ = Credential::verify_with_public_key(data, &[0u8; 1952]);
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use nexusq_core::identity::Credential;

fuzz_target!(|data: &[u8]| {
    let _ = nexusq_core::vault::from_slice::<Credential>(data);
});

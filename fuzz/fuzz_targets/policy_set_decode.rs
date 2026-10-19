#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::policy::PolicySet;

fuzz_target!(|data: &[u8]| {
    // Exercise PolicySet JSON deserialization with arbitrary input.
    // Malformed or adversarial policy documents must not panic.
    let _ = serde_json::from_slice::<PolicySet>(data);
});

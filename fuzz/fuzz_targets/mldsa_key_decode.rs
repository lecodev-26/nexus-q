#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::crypto::pq_sign::MlDsa65VerifyingKey;

fuzz_target!(|data: &[u8]| {
    // Exercise public-key decoding paths (including malformed lengths).
    let _ = MlDsa65VerifyingKey::from_public_key(data);
});

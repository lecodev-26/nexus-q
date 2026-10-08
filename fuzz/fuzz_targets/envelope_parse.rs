#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::crypto::kem::hybrid;
use nexusq_core::vault::from_slice;
use std::sync::OnceLock;

static PAIR: OnceLock<hybrid::KeyPair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let _: Result<nexusq_core::vault::Envelope, _> = from_slice(data);
    if data.len() >= 4 && data[..4] == *b"NQX1" {
        let pair = PAIR.get_or_init(|| hybrid::from_secret_key_bytes(&[0x42u8; 32]).expect("fixed fuzz key"));
        let _ = nexusq_core::vault::envelope::open_envelope_with_kem(pair, data);
    }
});

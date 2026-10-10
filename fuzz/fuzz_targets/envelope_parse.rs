#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::crypto::kem::hybrid;
use nexusq_core::vault::from_slice;
use std::sync::OnceLock;

static PAIR: OnceLock<hybrid::KeyPair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    // Exercise both deserialization and the full envelope-opening parser for every
    // input. The serialized envelope is CBOR; `NQX1` is a header field, not a
    // four-byte wire prefix, so checking `data[..4]` skipped valid CBOR envelopes.
    let _: Result<nexusq_core::vault::Envelope, _> = from_slice(data);
    let pair = PAIR.get_or_init(|| {
        hybrid::from_secret_key_bytes(&[0x42u8; 32]).expect("fixed fuzz key")
    });
    let _ = nexusq_core::vault::envelope::open_envelope_with_kem(pair, data);
});

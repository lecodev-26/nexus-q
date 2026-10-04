#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::vault::from_slice;
fuzz_target!(|data: &[u8]| {
    let _: Result<nexusq_core::vault::Envelope, _> = from_slice(data);
});

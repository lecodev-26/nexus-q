#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::vault::{serde_helpers, VaultBody};

fuzz_target!(|data: &[u8]| {
    let _: Result<VaultBody, _> = serde_helpers::from_slice(data);
});

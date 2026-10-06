#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::storage::AuditEvent;
use nexusq_core::vault::serde_helpers;

fuzz_target!(|data: &[u8]| {
    let _: Result<AuditEvent, _> = serde_helpers::from_slice(data);
});

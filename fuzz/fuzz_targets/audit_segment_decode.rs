#![no_main]

use libfuzzer_sys::fuzz_target;
use nexusq_core::storage::AuditSegment;

fuzz_target!(|data: &[u8]| {
    let _ = AuditSegment::from_bytes(data);
});

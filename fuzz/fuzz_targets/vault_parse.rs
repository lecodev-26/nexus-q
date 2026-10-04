#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::vault::Vault;
fuzz_target!(|data: &[u8]| {
    let path = std::env::temp_dir().join("nexusq-fuzz-vault.nqv");
    let _ = std::fs::write(&path, data);
    let _ = Vault::open(&path);
    let _ = std::fs::remove_file(path);
});

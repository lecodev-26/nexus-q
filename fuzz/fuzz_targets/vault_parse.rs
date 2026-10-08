#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::vault::Vault;
use tempfile::NamedTempFile;

fuzz_target!(|data: &[u8]| {
    let Ok(file) = NamedTempFile::new() else { return };
    let path = file.path();
    if std::fs::write(path, data).is_ok() {
        let _ = Vault::open(path);
    }
});

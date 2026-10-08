#![no_main]
use libfuzzer_sys::fuzz_target;
use nexusq_core::storage::backup;
use tempfile::NamedTempFile;

fuzz_target!(|data: &[u8]| {
    if !data.starts_with(b"NQB1") { return; }
    let Ok(input) = NamedTempFile::new() else { return };
    let Ok(output) = NamedTempFile::new() else { return };
    if std::fs::write(input.path(), data).is_ok() {
        let _ = backup::import(input.path(), b"fuzz-backup-password", output.path(), b"fuzz-vault-password");
    }
});

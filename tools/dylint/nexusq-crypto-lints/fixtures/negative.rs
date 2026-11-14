// Negative fixture: public metadata comparison and distinct nonce literals.
fn encrypt(_key: &[u8], _nonce: &[u8]) {}
fn ordinary_code(version: u32, supported_version: u32) {
    let _ = version == supported_version;
    let key = b"key";
    encrypt(key, b"nonce-one");
    encrypt(key, b"nonce-two");
}

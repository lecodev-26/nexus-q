// Positive fixture: review constant-time comparison and explicit nonce reuse.
fn encrypt(_key: &[u8], _nonce: &[u8]) {}
fn crypto_review(secret_key: &[u8], candidate: &[u8]) {
    let _ = secret_key == candidate;
    let key = b"key";
    encrypt(key, b"nonce-reused");
    encrypt(key, b"nonce-reused");
}

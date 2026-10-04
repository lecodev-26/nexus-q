use nexusq_core::crypto::{aead, kem, kem_1024, pq_sign, sign};
use nexusq_core::vault::Vault;
use std::hint::black_box;
use std::time::{Duration, Instant};
use tempfile::tempdir;

const N_CRYPTO: usize = 20;
const N_VAULT: usize = 3;

fn report(name: &str, n: usize, d: Duration) {
    println!("{name:34} {:12.0} ns/op", d.as_nanos() as f64 / n as f64);
}

fn main() {
    println!("NEXUS-Q Phase 17 benchmark (informational; Android/Termux)");
    println!("crypto iterations: {N_CRYPTO}; vault iterations: {N_VAULT}");

    let t = Instant::now();
    for _ in 0..N_CRYPTO {
        black_box(kem::hybrid::generate());
    }
    report("ML-KEM-768+X25519 keygen", N_CRYPTO, t.elapsed());

    let p = kem_1024::generate();
    let pk = p.public_key_bytes();
    let t = Instant::now();
    for _ in 0..N_CRYPTO {
        black_box(kem_1024::encapsulate(&pk).unwrap());
    }
    report("ML-KEM-1024+X25519 encaps", N_CRYPTO, t.elapsed());
    let ct = kem_1024::encapsulate(&pk).unwrap().0;
    let t = Instant::now();
    for _ in 0..N_CRYPTO {
        black_box(kem_1024::decapsulate(&p, &ct).unwrap());
    }
    report("ML-KEM-1024+X25519 decaps", N_CRYPTO, t.elapsed());

    let t = Instant::now();
    for _ in 0..N_CRYPTO {
        black_box(pq_sign::MlDsa65KeyPair::generate());
    }
    report("ML-DSA-65 keygen", N_CRYPTO, t.elapsed());
    let t = Instant::now();
    for _ in 0..N_CRYPTO {
        black_box(pq_sign::SlhDsaShake128fKeyPair::generate());
    }
    report("SLH-DSA-SHAKE-128f keygen", N_CRYPTO, t.elapsed());

    let ed = sign::generate();
    let msg = b"nexusq benchmark message";
    let sig = ed.signing.sign(msg);
    let vk = ed.signing.verifying_key();
    let t = Instant::now();
    for _ in 0..N_CRYPTO {
        black_box(ed.signing.sign(msg));
    }
    report("Ed25519 sign", N_CRYPTO, t.elapsed());
    let t = Instant::now();
    for _ in 0..N_CRYPTO {
        vk.verify(msg, &sig).unwrap();
        black_box(());
    }
    report("Ed25519 verify", N_CRYPTO, t.elapsed());

    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"nexusq-benchmark";
    let ciphertext = aead::encrypt(aead::Algorithm::Aes256Gcm, &key, &nonce, aad, msg).unwrap();
    let t = Instant::now();
    for _ in 0..N_CRYPTO {
        black_box(aead::encrypt(aead::Algorithm::Aes256Gcm, &key, &nonce, aad, msg).unwrap());
    }
    report("AES-256-GCM encrypt", N_CRYPTO, t.elapsed());
    let t = Instant::now();
    for _ in 0..N_CRYPTO {
        black_box(
            aead::decrypt(aead::Algorithm::Aes256Gcm, &key, &nonce, aad, &ciphertext).unwrap(),
        );
    }
    report("AES-256-GCM decrypt", N_CRYPTO, t.elapsed());

    let dir = tempdir().unwrap();
    let path = dir.path().join("bench.nqv");
    let password = b"phase17-benchmark-password";
    let vault = Vault::create(&path, password, Some("phase17".into())).unwrap();
    let t = Instant::now();
    for _ in 0..N_VAULT {
        black_box(Vault::open(&path).unwrap());
    }
    report("Vault open", N_VAULT, t.elapsed());

    let t = Instant::now();
    for _ in 0..N_VAULT {
        black_box(vault.unlock(password).unwrap());
    }
    report("Vault unlock", N_VAULT, t.elapsed());

    let mut session = vault.unlock(password).unwrap();
    let identity = session.create_identity(Some("benchmark".into())).unwrap();
    let t = Instant::now();
    for _ in 0..N_VAULT {
        black_box(session.rotate_identity_key(&identity).unwrap());
    }
    report("Identity key rotation", N_VAULT, t.elapsed());
}

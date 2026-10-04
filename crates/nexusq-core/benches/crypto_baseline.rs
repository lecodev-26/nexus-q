use nexusq_core::crypto::{aead, kem, kem_1024, pq_sign, sign};
use std::hint::black_box;
use std::time::{Duration, Instant};
fn report(name: &str, n: usize, d: Duration) {
    println!("{name:28} {:12.0} ns/op", d.as_nanos() as f64 / n as f64);
}
fn main() {
    const N: usize = 20;
    println!("NEXUS-Q crypto baseline ({N} iterations; informational)");
    let t = Instant::now();
    for _ in 0..N {
        black_box(kem::hybrid::generate());
    }
    report("ML-KEM-768+X25519 keygen", N, t.elapsed());
    let p = kem_1024::generate();
    let pk = p.public_key_bytes();
    let t = Instant::now();
    for _ in 0..N {
        black_box(kem_1024::encapsulate(&pk).unwrap());
    }
    report("ML-KEM-1024+X25519 encaps", N, t.elapsed());
    let t = Instant::now();
    for _ in 0..N {
        black_box(pq_sign::MlDsa65KeyPair::generate());
    }
    report("ML-DSA-65 keygen", N, t.elapsed());
    let t = Instant::now();
    for _ in 0..N {
        black_box(pq_sign::SlhDsaShake128fKeyPair::generate());
    }
    report("SLH-DSA-SHAKE-128f keygen", N, t.elapsed());
    let ed = sign::generate();
    let msg = b"nexusq benchmark message";
    let t = Instant::now();
    for _ in 0..N {
        black_box(ed.signing.sign(msg));
    }
    report("Ed25519 sign", N, t.elapsed());
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let t = Instant::now();
    for _ in 0..N {
        black_box(aead::encrypt(aead::Algorithm::Aes256Gcm, &key, &nonce, b"nexusq", msg).unwrap());
    }
    report("AES-256-GCM encrypt", N, t.elapsed());
}

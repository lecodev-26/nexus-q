use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, KeyExport, MlKem1024};
use nexusq_core::crypto::{kem::ml_kem_768, pq_sign};
use std::env;
use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const ITERATIONS: usize = 20;
const WARMUPS: usize = 3;
const MESSAGE: &[u8] = b"nexusq-pqc-arena-v1";
const ML_KEM_768_SECRET_KEY_LEN: usize = 2400;
const ML_KEM_1024_SECRET_KEY_LEN: usize = 3168;
const ML_DSA_65_SECRET_KEY_LEN: usize = 4032;

fn emit(
    algorithm: &str,
    parameter_set: &str,
    operation: &str,
    latency_ns: f64,
    sizes: serde_json::Value,
) {
    let obj = serde_json::json!({
        "schema_version": 1,
        "run_id": format!("nexusq-local-{}-{}-{}", algorithm, parameter_set, operation),
        "implementation": {"id":"nexusq","version":env!("CARGO_PKG_VERSION"),"commit":option_env!("NEXUSQ_COMMIT")},
        "algorithm": {"id":algorithm,"parameter_set":parameter_set},
        "operation": operation,
        "environment": {"target":format!("{}-{}",env::consts::ARCH,env::consts::OS),"os":env::consts::OS,"cpu":option_env!("NEXUSQ_CPU").unwrap_or("unknown"),"cpu_features":[],"compiler":"rustc","compiler_version":option_env!("RUSTC_VERSION").unwrap_or("unknown"),"optimization":option_env!("NEXUSQ_OPT").unwrap_or("unknown"),"harness_version":"arena-v1"},
        "measurement": {"iterations":ITERATIONS,"warmups":WARMUPS,"measurement_timestamp_unix_ns":SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock before Unix epoch").as_nanos(),"latency_ns":latency_ns,"throughput_ops_s":1_000_000_000.0/latency_ns,"memory_bytes":null,"measurement_method":"std::time::Instant mean wall-clock latency"},
        "sizes":sizes
    });
    println!("{}", serde_json::to_string(&obj).unwrap());
}

fn main() {
    let p768 = ml_kem_768::generate();
    let pk768 = ml_kem_768::public_key_bytes(&p768.1);
    let sk768_len = ML_KEM_768_SECRET_KEY_LEN;
    for _ in 0..WARMUPS {
        black_box(ml_kem_768::generate());
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(ml_kem_768::generate());
    }
    emit(
        "ml-kem",
        "768",
        "keygen",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        serde_json::json!({"public_key_bytes":pk768.len(),"secret_key_bytes":sk768_len,"ciphertext_bytes":ml_kem_768::CIPHERTEXT_LEN,"signature_bytes":null}),
    );
    let mut ct = Vec::new();
    for _ in 0..WARMUPS {
        let (c, s) = ml_kem_768::encapsulate(&p768.1);
        black_box((c, s));
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        let (c, s) = ml_kem_768::encapsulate(&p768.1);
        black_box(s);
        ct = c;
    }
    emit(
        "ml-kem",
        "768",
        "encaps",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        serde_json::json!({"public_key_bytes":pk768.len(),"secret_key_bytes":sk768_len,"ciphertext_bytes":ct.len(),"signature_bytes":null}),
    );
    for _ in 0..WARMUPS {
        black_box(ml_kem_768::decapsulate(&p768.0, &ct).unwrap());
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(ml_kem_768::decapsulate(&p768.0, &ct).unwrap());
    }
    emit(
        "ml-kem",
        "768",
        "decaps",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        serde_json::json!({"public_key_bytes":pk768.len(),"secret_key_bytes":sk768_len,"ciphertext_bytes":ct.len(),"signature_bytes":null}),
    );

    let (sk1024, pk1024): (DecapsulationKey1024, EncapsulationKey1024) =
        MlKem1024::generate_keypair();
    let pk1024_bytes = pk1024.to_bytes();
    let sk1024_bytes = ML_KEM_1024_SECRET_KEY_LEN;
    for _ in 0..WARMUPS {
        black_box(MlKem1024::generate_keypair());
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(MlKem1024::generate_keypair());
    }
    emit(
        "ml-kem",
        "1024",
        "keygen",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        serde_json::json!({"public_key_bytes":pk1024_bytes.len(),"secret_key_bytes":sk1024_bytes,"ciphertext_bytes":1568,"signature_bytes":null}),
    );
    let mut ct2 = Vec::new();
    for _ in 0..WARMUPS {
        let (c, s) = pk1024.encapsulate();
        black_box((c, s));
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        let (c, s) = pk1024.encapsulate();
        black_box(s);
        ct2 = c.as_slice().to_vec();
    }
    emit(
        "ml-kem",
        "1024",
        "encaps",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        serde_json::json!({"public_key_bytes":pk1024_bytes.len(),"secret_key_bytes":sk1024_bytes,"ciphertext_bytes":ct2.len(),"signature_bytes":null}),
    );
    let ct1024: ml_kem::ml_kem_1024::Ciphertext = ct2
        .clone()
        .try_into()
        .expect("ML-KEM-1024 ciphertext length");
    for _ in 0..WARMUPS {
        black_box(sk1024.decapsulate(&ct1024));
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(sk1024.decapsulate(&ct1024));
    }
    emit(
        "ml-kem",
        "1024",
        "decaps",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        serde_json::json!({"public_key_bytes":pk1024_bytes.len(),"secret_key_bytes":sk1024_bytes,"ciphertext_bytes":ct2.len(),"signature_bytes":null}),
    );

    let dsa = pq_sign::MlDsa65KeyPair::generate();
    let pk = dsa.public_key();
    let sig = dsa.sign(MESSAGE);
    for _ in 0..WARMUPS {
        black_box(pq_sign::MlDsa65KeyPair::generate());
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(pq_sign::MlDsa65KeyPair::generate());
    }
    emit(
        "ml-dsa",
        "65",
        "keygen",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        serde_json::json!({"public_key_bytes":pk.len(),"secret_key_bytes":ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":sig.len()}),
    );
    for _ in 0..WARMUPS {
        black_box(dsa.sign(MESSAGE));
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(dsa.sign(MESSAGE));
    }
    emit(
        "ml-dsa",
        "65",
        "sign",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        serde_json::json!({"public_key_bytes":pk.len(),"secret_key_bytes":ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":sig.len()}),
    );
    for _ in 0..WARMUPS {
        pq_sign::ml_dsa_65_verify(&pk, MESSAGE, &sig).unwrap();
        black_box(());
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        pq_sign::ml_dsa_65_verify(&pk, MESSAGE, &sig).unwrap();
        black_box(());
    }
    emit(
        "ml-dsa",
        "65",
        "verify",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        serde_json::json!({"public_key_bytes":pk.len(),"secret_key_bytes":ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":sig.len()}),
    );
}

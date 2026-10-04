use nexusq_core::crypto::{kem::ml_kem_768, kem_1024, pq_sign};
use std::env;
use std::hint::black_box;
use std::time::Instant;

const ITERATIONS: usize = 20;
const MESSAGE: &[u8] = b"nexusq-pqc-arena-v1";

fn emit(algorithm: &str, parameter_set: &str, operation: &str, latency_ns: f64, sizes: serde_json::Value) {
    let obj = serde_json::json!({
        "schema_version": 1,
        "run_id": format!("nexusq-local-{}-{}", algorithm, operation),
        "implementation": {"id":"nexusq","version":env!("CARGO_PKG_VERSION"),"commit":option_env!("NEXUSQ_COMMIT")},
        "algorithm": {"id":algorithm,"parameter_set":parameter_set},
        "operation": operation,
        "environment": {"target":format!("{}-{}",env::consts::ARCH,env::consts::OS),"os":env::consts::OS,"cpu":option_env!("NEXUSQ_CPU").unwrap_or("unknown"),"cpu_features":[],"compiler":"rustc","compiler_version":option_env!("RUSTC_VERSION").unwrap_or("unknown"),"optimization":option_env!("NEXUSQ_OPT").unwrap_or("unknown"),"harness_version":"arena-v1"},
        "measurement": {"iterations":ITERATIONS,"warmups":0,"latency_ns":latency_ns,"throughput_ops_s":1_000_000_000.0/latency_ns,"memory_bytes":null,"measurement_method":"std::time::Instant mean wall-clock latency"},
        "sizes":sizes
    });
    println!("{}", serde_json::to_string(&obj).unwrap());
}

fn main() {
    let p768=ml_kem_768::generate(); let pk768=ml_kem_768::public_key_bytes(&p768.1);
    let t=Instant::now(); for _ in 0..ITERATIONS { black_box(ml_kem_768::generate()); }
    emit("ml-kem","768","keygen",t.elapsed().as_nanos() as f64/ITERATIONS as f64,serde_json::json!({"public_key_bytes":pk768.len(),"secret_key_bytes":null,"ciphertext_bytes":ml_kem_768::CIPHERTEXT_LEN,"signature_bytes":null}));
    let mut ct=Vec::new(); let t=Instant::now(); for _ in 0..ITERATIONS { let (c,s)=ml_kem_768::encapsulate(&p768.1); black_box(s); ct=c; }
    emit("ml-kem","768","encaps",t.elapsed().as_nanos() as f64/ITERATIONS as f64,serde_json::json!({"public_key_bytes":pk768.len(),"secret_key_bytes":null,"ciphertext_bytes":ct.len(),"signature_bytes":null}));
    let t=Instant::now(); for _ in 0..ITERATIONS { black_box(ml_kem_768::decapsulate(&p768.0,&ct).unwrap()); }
    emit("ml-kem","768","decaps",t.elapsed().as_nanos() as f64/ITERATIONS as f64,serde_json::json!({"public_key_bytes":pk768.len(),"secret_key_bytes":null,"ciphertext_bytes":ct.len(),"signature_bytes":null}));

    let p1024=kem_1024::generate(); let pk1024=p1024.public_key_bytes();
    let t=Instant::now(); for _ in 0..ITERATIONS { black_box(kem_1024::generate()); }
    emit("ml-kem","1024","keygen",t.elapsed().as_nanos() as f64/ITERATIONS as f64,serde_json::json!({"public_key_bytes":pk1024.len(),"secret_key_bytes":kem_1024::SECRET_KEY_LEN,"ciphertext_bytes":kem_1024::CIPHERTEXT_LEN,"signature_bytes":null}));
    let mut ct2=Vec::new(); let t=Instant::now(); for _ in 0..ITERATIONS { let (c,s)=kem_1024::encapsulate(&pk1024).unwrap(); black_box(s); ct2=c; }
    emit("ml-kem","1024","encaps",t.elapsed().as_nanos() as f64/ITERATIONS as f64,serde_json::json!({"public_key_bytes":pk1024.len(),"secret_key_bytes":kem_1024::SECRET_KEY_LEN,"ciphertext_bytes":ct2.len(),"signature_bytes":null}));
    let t=Instant::now(); for _ in 0..ITERATIONS { black_box(kem_1024::decapsulate(&p1024,&ct2).unwrap()); }
    emit("ml-kem","1024","decaps",t.elapsed().as_nanos() as f64/ITERATIONS as f64,serde_json::json!({"public_key_bytes":pk1024.len(),"secret_key_bytes":kem_1024::SECRET_KEY_LEN,"ciphertext_bytes":ct2.len(),"signature_bytes":null}));

    let dsa=pq_sign::MlDsa65KeyPair::generate(); let pk=dsa.public_key(); let sig=dsa.sign(MESSAGE);
    let t=Instant::now(); for _ in 0..ITERATIONS { black_box(pq_sign::MlDsa65KeyPair::generate()); }
    emit("ml-dsa","65","keygen",t.elapsed().as_nanos() as f64/ITERATIONS as f64,serde_json::json!({"public_key_bytes":pk.len(),"secret_key_bytes":pq_sign::ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":sig.len()}));
    let t=Instant::now(); for _ in 0..ITERATIONS { black_box(dsa.sign(MESSAGE)); }
    emit("ml-dsa","65","sign",t.elapsed().as_nanos() as f64/ITERATIONS as f64,serde_json::json!({"public_key_bytes":pk.len(),"secret_key_bytes":pq_sign::ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":sig.len()}));
    let t=Instant::now(); for _ in 0..ITERATIONS { pq_sign::ml_dsa_65_verify(&pk,MESSAGE,&sig).unwrap(); black_box(()); }
    emit("ml-dsa","65","verify",t.elapsed().as_nanos() as f64/ITERATIONS as f64,serde_json::json!({"public_key_bytes":pk.len(),"secret_key_bytes":pq_sign::ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":sig.len()}));
}


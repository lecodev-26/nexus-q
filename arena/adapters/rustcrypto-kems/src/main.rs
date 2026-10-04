use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hqc_kem::{Hqc128, HqcKem};
use kem::{Decapsulate, Encapsulate, Generate};
use ml_kem::MlKem768;

const ITERATIONS: usize = 20;
const WARMUPS: usize = 3;

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn emit(
    algorithm: &str,
    parameter: &str,
    op: &str,
    latency_ns: f64,
    public_key: usize,
    secret_key: usize,
    ciphertext: Option<usize>,
) {
    let version = match algorithm {
        "ml-kem" => "0.3.2",
        "hqc" => "0.1.0-rc.0",
        _ => "unknown",
    };
    let commit = match algorithm {
        "ml-kem" => "440768245bba59784b504269cb3087a6c21af45c",
        "hqc" => "1a50023ab1dcebaaf500646589c76a3f0efade1f",
        _ => "unknown",
    };
    let row = serde_json::json!({
        "schema_version": 1,
        "run_id": format!("rustcrypto-{}-{}-{}", algorithm, parameter, op),
        "implementation": {"id":"rustcrypto-kems", "version":version, "commit":commit},
        "algorithm": {"id":algorithm, "parameter_set":parameter},
        "operation": op,
        "environment": {
            "target": std::env::var("ARENA_TARGET").unwrap_or_else(|_| "runtime".into()),
            "os": std::env::var("ARENA_OS").unwrap_or_else(|_| "runtime".into()),
            "cpu": std::env::var("ARENA_CPU").unwrap_or_else(|_| "runtime".into()),
            "cpu_features": [],
            "compiler": "rustc",
            "compiler_version": std::env::var("ARENA_COMPILER_VERSION").unwrap_or_else(|_| "runtime".into()),
            "optimization": std::env::var("ARENA_OPT").unwrap_or_else(|_| "release".into()),
            "harness_version": "arena-v1"
        },
        "measurement": {
            "iterations": ITERATIONS,
            "warmups": WARMUPS,
            "measurement_timestamp_unix_ns": now_ns(),
            "latency_ns": latency_ns,
            "throughput_ops_s": 1e9 / latency_ns,
            "memory_bytes": null,
            "measurement_method": "std::time::Instant mean wall-clock latency"
        },
        "sizes": {
            "public_key_bytes": public_key,
            "secret_key_bytes": secret_key,
            "ciphertext_bytes": ciphertext,
            "signature_bytes": null
        }
    });
    println!("{}", row);
}

fn ml_kem() {
    let (dk, ek) = MlKem768::generate_keypair();
    let pk_len = 1184usize;
    let sk_len = 2400usize;

    for _ in 0..WARMUPS {
        black_box(MlKem768::generate_keypair());
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(MlKem768::generate_keypair());
    }
    emit(
        "ml-kem",
        "768",
        "keygen",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        pk_len,
        sk_len,
        Some(1088),
    );

    let (ct, ss) = ek.encapsulate();
    for _ in 0..WARMUPS {
        black_box(ek.encapsulate());
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(ek.encapsulate());
    }
    emit(
        "ml-kem",
        "768",
        "encaps",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        pk_len,
        sk_len,
        Some(1088usize),
    );

    for _ in 0..WARMUPS {
        black_box(dk.decapsulate(&ct));
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(dk.decapsulate(&ct));
    }
    emit(
        "ml-kem",
        "768",
        "decaps",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        pk_len,
        sk_len,
        Some(1088usize),
    );
    black_box(ss);
}

fn hqc() {
    let mut rng = rand::rng();
    let (ek, dk) = Hqc128::generate_key(&mut rng);
    let pk_len = 2241usize;
    let sk_len = 2321usize;

    for _ in 0..WARMUPS {
        black_box(Hqc128::generate_key(&mut rng));
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(Hqc128::generate_key(&mut rng));
    }
    emit(
        "hqc",
        "128",
        "keygen",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        pk_len,
        sk_len,
        Some(4433),
    );

    let (ct, ss) = ek.encapsulate(&mut rng);
    for _ in 0..WARMUPS {
        black_box(ek.encapsulate(&mut rng));
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(ek.encapsulate(&mut rng));
    }
    emit(
        "hqc",
        "128",
        "encaps",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        pk_len,
        sk_len,
        Some(4433usize),
    );

    for _ in 0..WARMUPS {
        black_box(dk.decapsulate(&ct));
    }
    let t = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(dk.decapsulate(&ct));
    }
    emit(
        "hqc",
        "128",
        "decaps",
        t.elapsed().as_nanos() as f64 / ITERATIONS as f64,
        pk_len,
        sk_len,
        Some(4433usize),
    );
    black_box(ss);
}

fn main() {
    ml_kem();
    hqc();
}

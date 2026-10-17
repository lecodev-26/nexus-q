use nexusq_core::crypto::{kem, kem_1024, pq_sign};
use serde_json::json;
use std::env;
use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MESSAGE: &[u8] = b"nexusq-pqc-arena-v1";

fn count(name: &str, default: usize, min: usize) -> usize {
    match env::var(name) {
        Ok(v) => {
            let n: usize = v
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be an integer"));
            assert!(
                n >= min && n <= 1_000_000,
                "{name} outside [{min}, 1000000]"
            );
            n
        }
        Err(_) => default,
    }
}

fn stats(samples: &[u64]) -> (u64, u64, u64, f64) {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let median = if n % 2 == 0 {
        sorted[n / 2 - 1] / 2
            + sorted[n / 2] / 2
            + ((sorted[n / 2 - 1] % 2 + sorted[n / 2] % 2) / 2)
    } else {
        sorted[n / 2]
    };
    let p95 = sorted[(n * 95).div_ceil(100) - 1];
    let mean = samples.iter().map(|x| *x as f64).sum::<f64>() / n as f64;
    let variance = samples
        .iter()
        .map(|x| {
            let d = *x as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / n as f64;
    (sorted[0], median, p95, variance.sqrt())
}

fn measure<F: FnMut()>(
    operation: &str,
    algorithm: &str,
    parameter: &str,
    mut f: F,
    warmups: usize,
    iterations: usize,
) {
    for _ in 0..warmups {
        f();
    }
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        samples.push(start.elapsed().as_nanos().max(1).min(u64::MAX as u128) as u64);
    }
    let (min, median, p95, stddev) = stats(&samples);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let implementation = env::var("CORE_IMPL").unwrap_or_else(|_| "nexusq-core-rustcrypto".into());
    let commit = env::var("CORE_COMMIT")
        .or_else(|_| env::var("GITHUB_SHA"))
        .unwrap_or_else(|_| "local".into());
    let cpu = env::var("CORE_CPU").unwrap_or_else(|_| "unknown".into());
    let cpu_features = env::var("CORE_CPU_FEATURES").unwrap_or_default();
    let features = cpu_features
        .split(',')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let order = env::var("CORE_RUN_ORDER").unwrap_or_else(|_| "unknown".into());
    let rustc = env::var("RUSTC_VERSION").unwrap_or_else(|_| "unknown".into());
    let method = "per-operation Instant wall-clock samples through public nexusq-core crypto API; median and nearest-rank p95 from raw samples";
    println!(
        "{}",
        json!({
            "schema_version": 1,
            "run_id": format!("{}-{}-{}-{}-{}-{}", implementation, commit, order, algorithm, parameter, operation),
            "implementation": {"id": implementation, "version": "pr-head", "commit": commit},
            "algorithm": {"id": algorithm, "parameter_set": parameter},
            "operation": operation,
            "environment": {"target": env::consts::ARCH, "os": env::consts::OS, "cpu": cpu,
                "cpu_features": features, "compiler": "rustc", "compiler_version": rustc,
                "optimization": "release", "run_order": order, "harness_version": "nexusq-core-production-v1"},
            "measurement": {"iterations": iterations, "warmups": warmups,
                "measurement_timestamp_unix_ns": now, "latency_ns": median,
                "throughput_ops_s": 1e9 / median as f64, "measurement_method": method,
                "measurement_scope": if algorithm == "ml-kem" && parameter == "1024" { "nexusq_core_hybrid_public_api" } else { "nexusq_core_public_api" }, "comparison_contract": "fips_operation_v1",
                "samples_ns": samples, "statistics": {"sample_count": iterations, "min_ns": min, "median_ns": median, "p95_ns": p95, "stddev_ns": stddev},
                "memory_bytes": null},
            "sizes": {"public_key_bytes": null, "secret_key_bytes": null, "ciphertext_bytes": null, "signature_bytes": null}
        })
    );
}

fn main() {
    let iterations = count("CORE_ITERATIONS", 1000, 100);
    let warmups = count("CORE_WARMUPS", 100, 0);
    let commit = env::var("CORE_COMMIT")
        .or_else(|_| env::var("GITHUB_SHA"))
        .unwrap_or_else(|_| "local".into());
    let cpu = env::var("CORE_CPU").unwrap_or_else(|_| "unknown".into());
    eprintln!(
        "production benchmark commit={commit} cpu={cpu} iterations={iterations} warmups={warmups} feature_native={}",
        cfg!(feature = "native-backend")
    );

    measure(
        "keygen",
        "ml-kem",
        "768",
        || {
            black_box(kem::ml_kem_768::generate());
        },
        warmups,
        iterations,
    );
    let (sk768, pk768) = kem::ml_kem_768::generate();
    measure(
        "encaps",
        "ml-kem",
        "768",
        || {
            black_box(kem::ml_kem_768::encapsulate(&pk768));
        },
        warmups,
        iterations,
    );
    let (ct768, ss768) = kem::ml_kem_768::encapsulate(&pk768);
    let recovered768 = kem::ml_kem_768::decapsulate(&sk768, &ct768).unwrap();
    assert_eq!(
        &*ss768, &*recovered768,
        "ML-KEM-768 pre-benchmark round trip failed"
    );
    measure(
        "decaps",
        "ml-kem",
        "768",
        || {
            black_box(kem::ml_kem_768::decapsulate(&sk768, &ct768).unwrap());
        },
        warmups,
        iterations,
    );

    measure(
        "keygen",
        "ml-kem",
        "1024",
        || {
            black_box(kem_1024::generate());
        },
        warmups,
        iterations,
    );
    let pair1024 = kem_1024::generate();
    // Validate the serialized wire path once; time the prepared-key path so the
    // gate matches AWS-LC's prepared EVP context model.
    let public1024 = pair1024.public_key_bytes();
    let (ct_ser, ss_ser) = kem_1024::encapsulate(&public1024).unwrap();
    let recovered_ser = kem_1024::decapsulate(&pair1024, &ct_ser).unwrap();
    assert_eq!(
        &*ss_ser, &*recovered_ser,
        "ML-KEM-1024 hybrid serialized pre-benchmark round trip failed"
    );
    // Preallocate ciphertext/secret buffers outside the timed samples so the
    // gate matches AWS-LC (EVP context + output buffers kept outside the loop).
    let mut ct_buf = [0u8; kem_1024::CIPHERTEXT_LEN];
    let mut ss_buf = [0u8; 32];
    pair1024
        .encapsulate_prepared_into(&mut ct_buf, &mut ss_buf)
        .expect("prepared encaps setup");
    let recovered_setup = kem_1024::decapsulate(&pair1024, &ct_buf).unwrap();
    assert_eq!(
        ss_buf, *recovered_setup,
        "ML-KEM-1024 hybrid prepared pre-benchmark round trip failed"
    );
    measure(
        "encaps",
        "ml-kem",
        "1024",
        || {
            pair1024
                .encapsulate_prepared_into(&mut ct_buf, &mut ss_buf)
                .unwrap();
            black_box((&ct_buf, &ss_buf));
        },
        warmups,
        iterations,
    );
    let ct1024 = ct_buf.to_vec();
    let ss1024 = ss_buf;
    let recovered1024 = kem_1024::decapsulate(&pair1024, &ct1024).unwrap();
    assert_eq!(
        ss1024, *recovered1024,
        "ML-KEM-1024 hybrid prepared post-setup round trip failed"
    );
    let mut decaps_ss = [0u8; 32];
    measure(
        "decaps",
        "ml-kem",
        "1024",
        || {
            kem_1024::decapsulate_into(&pair1024, &ct1024, &mut decaps_ss).unwrap();
            black_box(&decaps_ss);
        },
        warmups,
        iterations,
    );

    measure(
        "keygen",
        "ml-dsa",
        "65",
        || {
            black_box(pq_sign::MlDsa65KeyPair::generate());
        },
        warmups,
        iterations,
    );
    let key = pq_sign::MlDsa65KeyPair::generate();
    let signature = key.sign(MESSAGE);
    let public = key.public_key();
    measure(
        "sign",
        "ml-dsa",
        "65",
        || {
            black_box(key.sign(MESSAGE));
        },
        warmups,
        iterations,
    );
    let verifier = pq_sign::MlDsa65VerifyingKey::from_public_key(&public)
        .expect("benchmark public key is valid");
    verifier
        .verify(MESSAGE, &signature)
        .expect("ML-DSA-65 pre-benchmark verification failed");
    measure(
        "verify",
        "ml-dsa",
        "65",
        || {
            black_box(verifier.verify(MESSAGE, &signature).unwrap());
        },
        warmups,
        iterations,
    );
}

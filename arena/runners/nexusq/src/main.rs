use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{
    DecapsulationKey768, DecapsulationKey1024, EncapsulationKey768, EncapsulationKey1024,
    KeyExport, MlKem768, MlKem1024,
};
use nexusq_core::crypto::pq_sign;
use std::env;
use std::hint::black_box;
use std::sync::Mutex;

mod cycles {
    //! Raw hardware-counter instrumentation; ticks are not assumed to be nanoseconds.
    #[inline]
    pub fn read() -> Option<u64> {
        #[cfg(target_arch = "x86_64")]
        {
            let low: u32;
            let high: u32;
            // SAFETY: LFENCE orders RDTSC after prior instructions; outputs are explicit
            // and the instruction does not access memory.
            unsafe {
                core::arch::asm!(
                    "lfence", "rdtsc", "lfence",
                    out("eax") low, out("edx") high,
                    options(nostack, preserves_flags)
                );
            }
            return Some(((high as u64) << 32) | low as u64);
        }
        #[cfg(target_arch = "aarch64")]
        {
            let counter: u64;
            // SAFETY: ISB orders the architectural counter read; MRS writes one register.
            unsafe {
                core::arch::asm!(
                    "isb", "mrs {counter}, cntvct_el0",
                    counter = out(reg) counter,
                    options(nostack, preserves_flags)
                );
            }
            return Some(counter);
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { None }
    }

    pub const fn source() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        { return "x86_64_tsc_ticks"; }
        #[cfg(target_arch = "aarch64")]
        { return "aarch64_cntvct_ticks"; }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        { "unavailable" }
    }
}

static CYCLE_SAMPLES: Mutex<Vec<u64>> = Mutex::new(Vec::new());

#[inline]
fn cycle_delta(start: Option<u64>) -> Option<u64> {
    start.zip(cycles::read()).map(|(start, end)| end.wrapping_sub(start))
}

#[inline]
fn record_cycles(sample: Option<u64>) {
    if let Some(sample) = sample {
        if let Ok(mut samples) = CYCLE_SAMPLES.lock() {
            samples.push(sample);
        }
    }
}

fn take_cycle_samples() -> Vec<u64> {
    CYCLE_SAMPLES.lock().map(|mut samples| std::mem::take(&mut *samples)).unwrap_or_default()
}
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_ITERATIONS: usize = 1_000;
const DEFAULT_WARMUPS: usize = 100;

fn configured_count(name: &str, default: usize, minimum: usize) -> usize {
    match env::var(name) {
        Ok(value) => {
            let parsed = value.parse::<usize>().unwrap_or_else(|_| {
                eprintln!("{name} must be a positive integer; got {value:?}");
                std::process::exit(2);
            });
            if parsed < minimum {
                eprintln!("{name} must be at least {minimum}; got {parsed}");
                std::process::exit(2);
            }
            parsed
        }
        Err(_) => default,
    }
}

fn iterations() -> usize {
    configured_count("NEXUSQ_ITERATIONS", DEFAULT_ITERATIONS, 1)
}

fn warmups() -> usize {
    configured_count("NEXUSQ_WARMUPS", DEFAULT_WARMUPS, 0)
}
const ML_DSA_SIGN_SEEDS: usize = 64;
const DEFAULT_ML_DSA_SIGN_SAMPLES_PER_SEED: usize = 16;

fn ml_dsa_sign_samples_per_seed() -> usize {
    configured_count(
        "NEXUSQ_SIGN_SAMPLES_PER_SEED",
        DEFAULT_ML_DSA_SIGN_SAMPLES_PER_SEED,
        1,
    )
}
const MESSAGE: &[u8] = b"nexusq-pqc-arena-v1";
const ML_KEM_768_SECRET_KEY_LEN: usize = 2400;
const ML_KEM_1024_SECRET_KEY_LEN: usize = 3168;
const ML_DSA_65_SECRET_KEY_LEN: usize = 4032;

fn median(sorted: &[u128]) -> u128 {
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        let lower = sorted[middle - 1];
        let upper = sorted[middle];
        lower + (upper - lower) / 2
    } else {
        sorted[middle]
    }
}

fn nearest_rank_percentile(sorted: &[u128], percentile: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((sorted.len() as f64) * percentile).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn summary(samples: &[u128]) -> serde_json::Value {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let mean = samples.iter().map(|x| *x as f64).sum::<f64>() / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|x| {
            let delta = *x as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / samples.len() as f64;
    serde_json::json!({
        "sample_count": samples.len(),
        "min_ns": sorted.first().copied().unwrap_or_default(),
        "median_ns": median(&sorted),
        "p95_ns": nearest_rank_percentile(&sorted, 0.95),
        "stddev_ns": variance.sqrt(),
    })
}

fn emit_operation_samples(
    algorithm: &str,
    parameter_set: &str,
    operation: &str,
    samples: &[u128],
    sizes: serde_json::Value,
) {
    assert!(
        !samples.is_empty(),
        "benchmark sample set must not be empty"
    );
    let stats = summary(samples);
    let cycle_samples = take_cycle_samples();
    let latency_ns = stats["median_ns"].as_u64().unwrap_or(1) as f64;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let obj = serde_json::json!({
        "schema_version": 1,
        "run_id": format!("{}-{}-{}-{}-{}", env::var("NEXUSQ_RUN_ID").unwrap_or_else(|_| "nexusq-local".into()), algorithm, parameter_set, operation, samples.len()),
        "implementation": {"id":"nexusq","version":env!("CARGO_PKG_VERSION"),"commit":option_env!("NEXUSQ_COMMIT").or_else(|| Some("unknown"))},
        "algorithm": {"id":algorithm,"parameter_set":parameter_set},
        "operation": operation,
        "environment": {
            "target":format!("{}-{}",env::consts::ARCH,env::consts::OS), "os":env::consts::OS,
            "cpu":env::var("NEXUSQ_CPU").unwrap_or_else(|_| "unknown".into()),
            "cpu_features":env::var("NEXUSQ_CPU_FEATURES").unwrap_or_default().split(',').filter(|x| !x.is_empty()).collect::<Vec<_>>(),
            "compiler":"rustc", "compiler_version":env::var("RUSTC_VERSION").unwrap_or_else(|_| "unknown".into()),
            "rustc_verbose":env::var("NEXUSQ_RUSTC_VERBOSE").unwrap_or_else(|_| "unknown".into()),
            "cargo_lock_sha256":env::var("NEXUSQ_CARGO_LOCK_SHA256").unwrap_or_else(|_| "unknown".into()),
            "cpu_frequency_khz":env::var("NEXUSQ_CPU_FREQUENCY_KHZ").ok().and_then(|x| x.parse::<u64>().ok()),
            "cpu_governor":env::var("NEXUSQ_CPU_GOVERNOR").unwrap_or_else(|_| "unknown".into()),
            "run_order":env::var("NEXUSQ_RUN_ORDER").unwrap_or_else(|_| "unknown".into()),
            "optimization":env::var("NEXUSQ_OPT").unwrap_or_else(|_| "unknown".into()), "harness_version":"arena-v4-cycle-counter"
        },
        "measurement": {
            "iterations":samples.len(), "warmups":warmups(),
            "measurement_timestamp_unix_ns":timestamp, "latency_ns":latency_ns,
            "throughput_ops_s":1_000_000_000.0/latency_ns, "memory_bytes":null,
            "measurement_method":if algorithm == "ml-kem" {
                "per-operation std::time::Instant; direct RustCrypto ml-kem API; median latency"
            } else {
                "per-operation std::time::Instant; nexusq-core ML-DSA wrapper; median latency"
            },
            "measurement_scope":if algorithm == "ml-kem" {
                "rustcrypto_ml_kem_operation"
            } else {
                "nexusq_core_ml_dsa_wrapper_operation"
            },
            "samples_ns":samples, "statistics":stats,
            "cycle_counter_source":cycles::source(), "samples_cycles":cycle_samples
        },
        "sizes":sizes
    });
    println!("{}", serde_json::to_string(&obj).unwrap());
}

fn emit_cached_verify_samples(samples: &[u128], public_key_len: usize, signature_len: usize) {
    let stats = summary(samples);
    let cycle_samples = take_cycle_samples();
    let latency_ns = stats["median_ns"].as_u64().unwrap_or(1) as f64;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let obj = serde_json::json!({
        "schema_version": 1,
        "run_id": format!("{}-ml-dsa-65-cached-verify-{}", env::var("NEXUSQ_RUN_ID").unwrap_or_else(|_| "nexusq-local".into()), samples.len()),
        "implementation": {"id":"nexusq","version":env!("CARGO_PKG_VERSION"),"commit":option_env!("NEXUSQ_COMMIT").or_else(|| Some("unknown"))},
        "algorithm": {"id":"ml-dsa","parameter_set":"65"},
        "operation":"verify",
        "environment": {
            "target":format!("{}-{}",env::consts::ARCH,env::consts::OS), "os":env::consts::OS,
            "cpu":env::var("NEXUSQ_CPU").unwrap_or_else(|_| "unknown".into()),
            "cpu_features":env::var("NEXUSQ_CPU_FEATURES").unwrap_or_default().split(',').filter(|x| !x.is_empty()).collect::<Vec<_>>(),
            "compiler":"rustc", "compiler_version":env::var("RUSTC_VERSION").unwrap_or_else(|_| "unknown".into()),
            "rustc_verbose":env::var("NEXUSQ_RUSTC_VERBOSE").unwrap_or_else(|_| "unknown".into()),
            "cargo_lock_sha256":env::var("NEXUSQ_CARGO_LOCK_SHA256").unwrap_or_else(|_| "unknown".into()),
            "cpu_frequency_khz":env::var("NEXUSQ_CPU_FREQUENCY_KHZ").ok().and_then(|x| x.parse::<u64>().ok()),
            "cpu_governor":env::var("NEXUSQ_CPU_GOVERNOR").unwrap_or_else(|_| "unknown".into()),
            "run_order":env::var("NEXUSQ_RUN_ORDER").unwrap_or_else(|_| "unknown".into()),
            "optimization":env::var("NEXUSQ_OPT").unwrap_or_else(|_| "unknown".into()), "harness_version":"arena-v4-cycle-counter"
        },
        "measurement": {
            "iterations":samples.len(), "warmups":warmups(),
            "measurement_timestamp_unix_ns":timestamp, "latency_ns":latency_ns,
            "throughput_ops_s":1_000_000_000.0/latency_ns, "memory_bytes":null,
            "measurement_method":"per-operation std::time::Instant; cached MlDsa65VerifyingKey",
            "measurement_scope":"cached_ml_dsa_verifier_operation",
            "samples_ns":samples, "statistics":stats,
            "cycle_counter_source":cycles::source(), "samples_cycles":cycle_samples
        },
        "sizes":{"public_key_bytes":public_key_len,"secret_key_bytes":ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":signature_len}
    });
    println!("{}", serde_json::to_string(&obj).unwrap());
}

fn emit_ml_dsa_sign_distribution(
    keys: &[pq_sign::MlDsa65KeyPair],
    seed_ids: &[String],
    public_key: &[u8],
    signature_len: usize,
) {
    let mut per_seed = Vec::with_capacity(keys.len());
    let mut all_samples = Vec::with_capacity(keys.len() * ml_dsa_sign_samples_per_seed());
    for (key, seed_id) in keys.iter().zip(seed_ids) {
        for _ in 0..warmups() {
            black_box(black_box(key).sign(black_box(MESSAGE)));
        }
        let mut samples = Vec::with_capacity(ml_dsa_sign_samples_per_seed());
        for _ in 0..ml_dsa_sign_samples_per_seed() {
            let cycle_start = cycles::read();
            let start = Instant::now();
            black_box(black_box(key).sign(black_box(MESSAGE)));
            let cycle_sample = cycle_delta(cycle_start);
            let elapsed = start.elapsed().as_nanos();
            record_cycles(cycle_sample);
            samples.push(elapsed);
        }
        all_samples.extend_from_slice(&samples);
        per_seed.push(serde_json::json!({
            "seed_id": seed_id,
            "samples_ns": samples,
            "summary": summary(&all_samples[all_samples.len() - samples.len()..]),
        }));
    }
    let overall = summary(&all_samples);
    let cycle_samples = take_cycle_samples();
    let latency_ns = overall["median_ns"].as_u64().unwrap_or(1) as f64;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let obj = serde_json::json!({
        "schema_version": 1,
        "run_id": format!("{}-ml-dsa-65-sign-distribution-{}x{}", env::var("NEXUSQ_RUN_ID").unwrap_or_else(|_| "nexusq-local".into()), keys.len(), ml_dsa_sign_samples_per_seed()),
        "implementation": {"id":"nexusq","version":env!("CARGO_PKG_VERSION"),"commit":option_env!("NEXUSQ_COMMIT").or_else(|| Some("unknown"))},
        "algorithm": {"id":"ml-dsa","parameter_set":"65"},
        "operation": "sign",
        "environment": {
            "target":format!("{}-{}",env::consts::ARCH,env::consts::OS),
            "os":env::consts::OS,
            "cpu":env::var("NEXUSQ_CPU").unwrap_or_else(|_| "unknown".into()),
            "cpu_features":env::var("NEXUSQ_CPU_FEATURES").unwrap_or_default().split(',').filter(|x| !x.is_empty()).collect::<Vec<_>>(),
            "compiler":"rustc",
            "compiler_version":env::var("RUSTC_VERSION").unwrap_or_else(|_| "unknown".into()),
            "rustc_verbose":env::var("NEXUSQ_RUSTC_VERBOSE").unwrap_or_else(|_| "unknown".into()),
            "cargo_lock_sha256":env::var("NEXUSQ_CARGO_LOCK_SHA256").unwrap_or_else(|_| "unknown".into()),
            "cpu_frequency_khz":env::var("NEXUSQ_CPU_FREQUENCY_KHZ").ok().and_then(|x| x.parse::<u64>().ok()),
            "cpu_governor":env::var("NEXUSQ_CPU_GOVERNOR").unwrap_or_else(|_| "unknown".into()),
            "run_order":env::var("NEXUSQ_RUN_ORDER").unwrap_or_else(|_| "unknown".into()),
            "optimization":env::var("NEXUSQ_OPT").unwrap_or_else(|_| "unknown".into()),
            "harness_version":"arena-v4-cycle-counter"
        },
        "measurement": {
            "iterations":all_samples.len(),
            "warmups":warmups() * keys.len(),
            "measurement_timestamp_unix_ns":timestamp,
            "latency_ns":latency_ns,
            "throughput_ops_s":1_000_000_000.0 / latency_ns,
            "memory_bytes":null,
            "measurement_method":"per-sign std::time::Instant; nexusq-core ML-DSA wrapper; deterministic 64-key seed corpus; fixed message",
            "measurement_scope":"nexusq_core_ml_dsa_wrapper_operation",
            "samples_ns":all_samples,
            "statistics":overall,
            "seed_samples":per_seed,
            "cycle_counter_source":cycles::source(),
            "samples_cycles":cycle_samples,
            "seed_count":keys.len(),
            "samples_per_seed":ml_dsa_sign_samples_per_seed()
        },
        "sizes":{"public_key_bytes":public_key.len(),"secret_key_bytes":ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":signature_len}
    });
    println!("{}", serde_json::to_string(&obj).unwrap());
}

fn deterministic_seed(index: usize) -> [u8; 32] {
    // SplitMix64 expands a public, fixed benchmark index into reproducible seed
    // material. These seeds are benchmark fixtures, never production keys.
    let mut state = (index as u64).wrapping_add(0x9E3779B97F4A7C15);
    let mut seed = [0u8; 32];
    for chunk in seed.chunks_exact_mut(8) {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes());
    }
    seed
}

#[cfg(test)]
mod statistics_tests {
    use super::{median, nearest_rank_percentile};

    #[test]
    fn median_averages_the_middle_pair_for_even_sample_counts() {
        assert_eq!(median(&[10, 20]), 15);
        assert_eq!(median(&[10, 20, 30, 40]), 25);
    }

    #[test]
    fn median_selects_the_middle_value_for_odd_sample_counts() {
        assert_eq!(median(&[10, 20, 30]), 20);
    }

    #[test]
    fn p95_uses_the_nearest_rank_definition_shared_with_aws_lc() {
        let samples: Vec<u128> = (1..=1000).collect();
        assert_eq!(nearest_rank_percentile(&samples, 0.95), 950);
    }
}

fn main() {
    let (sk768, pk768): (DecapsulationKey768, EncapsulationKey768) = MlKem768::generate_keypair();
    let (check_ct768, check_ss768) = pk768.encapsulate();
    let check_dec_ss768 = sk768.decapsulate(&check_ct768);
    assert_eq!(
        check_ss768.as_slice(),
        check_dec_ss768.as_slice(),
        "ML-KEM-768 self-check failed"
    );
    let pk768_bytes = pk768.to_bytes();
    let sk768_len = ML_KEM_768_SECRET_KEY_LEN;
    for _ in 0..warmups() {
        black_box(MlKem768::generate_keypair());
    }
    let mut samples = Vec::with_capacity(iterations());
    for _ in 0..iterations() {
        let cycle_start = cycles::read();
        let start = Instant::now();
        black_box(MlKem768::generate_keypair());
        let cycle_sample = cycle_delta(cycle_start);
        let elapsed = start.elapsed().as_nanos();
        record_cycles(cycle_sample);
        samples.push(elapsed);
    }
    emit_operation_samples(
        "ml-kem",
        "768",
        "keygen",
        &samples,
        serde_json::json!({"public_key_bytes":pk768_bytes.len(),"secret_key_bytes":sk768_len,"ciphertext_bytes":1088,"signature_bytes":null}),
    );
    for _ in 0..warmups() {
        let (c, s) = black_box(&pk768).encapsulate();
        black_box((c, s));
    }
    let mut ct768_bytes = Vec::new();
    let mut samples = Vec::with_capacity(iterations());
    for _ in 0..iterations() {
        let cycle_start = cycles::read();
        let start = Instant::now();
        let (c, s) = black_box(&pk768).encapsulate();
        black_box(s);
        let cycle_sample = cycle_delta(cycle_start);
        let elapsed = start.elapsed().as_nanos();
        record_cycles(cycle_sample);
        // Keep ciphertext serialization/copying outside the timed primitive call.
        ct768_bytes = c.as_slice().to_vec();
        samples.push(elapsed);
    }
    emit_operation_samples(
        "ml-kem",
        "768",
        "encaps",
        &samples,
        serde_json::json!({"public_key_bytes":pk768_bytes.len(),"secret_key_bytes":sk768_len,"ciphertext_bytes":ct768_bytes.len(),"signature_bytes":null}),
    );
    let ct768: ml_kem::ml_kem_768::Ciphertext = ct768_bytes
        .clone()
        .try_into()
        .expect("ML-KEM-768 ciphertext length");
    for _ in 0..warmups() {
        black_box(black_box(&sk768).decapsulate(black_box(&ct768)));
    }
    let mut samples = Vec::with_capacity(iterations());
    for _ in 0..iterations() {
        let cycle_start = cycles::read();
        let start = Instant::now();
        black_box(black_box(&sk768).decapsulate(black_box(&ct768)));
        let cycle_sample = cycle_delta(cycle_start);
        let elapsed = start.elapsed().as_nanos();
        record_cycles(cycle_sample);
        samples.push(elapsed);
    }
    emit_operation_samples(
        "ml-kem",
        "768",
        "decaps",
        &samples,
        serde_json::json!({"public_key_bytes":pk768_bytes.len(),"secret_key_bytes":sk768_len,"ciphertext_bytes":ct768_bytes.len(),"signature_bytes":null}),
    );

    let (sk1024, pk1024): (DecapsulationKey1024, EncapsulationKey1024) =
        MlKem1024::generate_keypair();
    let (check_ct1024, check_ss1024) = pk1024.encapsulate();
    let check_dec_ss1024 = sk1024.decapsulate(&check_ct1024);
    assert_eq!(
        check_ss1024.as_slice(),
        check_dec_ss1024.as_slice(),
        "ML-KEM-1024 self-check failed"
    );
    let pk1024_bytes = pk1024.to_bytes();
    let sk1024_bytes = ML_KEM_1024_SECRET_KEY_LEN;
    for _ in 0..warmups() {
        black_box(MlKem1024::generate_keypair());
    }
    let mut samples = Vec::with_capacity(iterations());
    for _ in 0..iterations() {
        let cycle_start = cycles::read();
        let start = Instant::now();
        black_box(MlKem1024::generate_keypair());
        let cycle_sample = cycle_delta(cycle_start);
        let elapsed = start.elapsed().as_nanos();
        record_cycles(cycle_sample);
        samples.push(elapsed);
    }
    emit_operation_samples(
        "ml-kem",
        "1024",
        "keygen",
        &samples,
        serde_json::json!({"public_key_bytes":pk1024_bytes.len(),"secret_key_bytes":sk1024_bytes,"ciphertext_bytes":1568,"signature_bytes":null}),
    );
    let mut ct2 = Vec::new();
    for _ in 0..warmups() {
        let (c, s) = black_box(&pk1024).encapsulate();
        black_box((c, s));
    }
    let mut samples = Vec::with_capacity(iterations());
    for _ in 0..iterations() {
        let cycle_start = cycles::read();
        let start = Instant::now();
        let (c, s) = black_box(&pk1024).encapsulate();
        black_box(s);
        let cycle_sample = cycle_delta(cycle_start);
        let elapsed = start.elapsed().as_nanos();
        record_cycles(cycle_sample);
        // Keep serialization/copying the ciphertext outside the timed primitive call.
        ct2 = c.as_slice().to_vec();
        samples.push(elapsed);
    }
    emit_operation_samples(
        "ml-kem",
        "1024",
        "encaps",
        &samples,
        serde_json::json!({"public_key_bytes":pk1024_bytes.len(),"secret_key_bytes":sk1024_bytes,"ciphertext_bytes":ct2.len(),"signature_bytes":null}),
    );
    let ct1024: ml_kem::ml_kem_1024::Ciphertext = ct2
        .clone()
        .try_into()
        .expect("ML-KEM-1024 ciphertext length");
    for _ in 0..warmups() {
        black_box(black_box(&sk1024).decapsulate(black_box(&ct1024)));
    }
    let mut samples = Vec::with_capacity(iterations());
    for _ in 0..iterations() {
        let cycle_start = cycles::read();
        let start = Instant::now();
        black_box(black_box(&sk1024).decapsulate(black_box(&ct1024)));
        let cycle_sample = cycle_delta(cycle_start);
        let elapsed = start.elapsed().as_nanos();
        record_cycles(cycle_sample);
        samples.push(elapsed);
    }
    emit_operation_samples(
        "ml-kem",
        "1024",
        "decaps",
        &samples,
        serde_json::json!({"public_key_bytes":pk1024_bytes.len(),"secret_key_bytes":sk1024_bytes,"ciphertext_bytes":ct2.len(),"signature_bytes":null}),
    );

    let dsa = pq_sign::MlDsa65KeyPair::generate();
    let pk = dsa.public_key();
    let sig = dsa.sign(MESSAGE);
    for _ in 0..warmups() {
        black_box(pq_sign::MlDsa65KeyPair::generate());
    }
    let mut samples = Vec::with_capacity(iterations());
    for _ in 0..iterations() {
        let cycle_start = cycles::read();
        let start = Instant::now();
        black_box(pq_sign::MlDsa65KeyPair::generate());
        let cycle_sample = cycle_delta(cycle_start);
        let elapsed = start.elapsed().as_nanos();
        record_cycles(cycle_sample);
        samples.push(elapsed);
    }
    emit_operation_samples(
        "ml-dsa",
        "65",
        "keygen",
        &samples,
        serde_json::json!({"public_key_bytes":pk.len(),"secret_key_bytes":ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":sig.len()}),
    );
    let mut sign_keys = Vec::with_capacity(ML_DSA_SIGN_SEEDS);
    let mut seed_ids = Vec::with_capacity(ML_DSA_SIGN_SEEDS);
    for index in 0..ML_DSA_SIGN_SEEDS {
        let seed = deterministic_seed(index);
        sign_keys.push(
            pq_sign::MlDsa65KeyPair::from_secret_key(&seed).expect("fixed benchmark seed is valid"),
        );
        seed_ids.push(format!("seed-{index:03}"));
    }
    emit_ml_dsa_sign_distribution(&sign_keys, &seed_ids, &pk, sig.len());
    #[cfg(feature = "cached-verifier")]
    {
        let cached_verifier = pq_sign::MlDsa65VerifyingKey::from_public_key(&pk)
            .expect("generated public key is valid");
        for _ in 0..warmups() {
            black_box(black_box(&cached_verifier).verify(black_box(MESSAGE), black_box(&sig))).unwrap();
        }
        let mut cached_verify_samples = Vec::with_capacity(iterations());
        for _ in 0..iterations() {
            let cycle_start = cycles::read();
            let start = Instant::now();
            black_box(black_box(&cached_verifier).verify(black_box(MESSAGE), black_box(&sig))).unwrap();
            let cycle_sample = cycle_delta(cycle_start);
            let elapsed = start.elapsed().as_nanos();
            record_cycles(cycle_sample);
            cached_verify_samples.push(elapsed);
        }
        emit_cached_verify_samples(&cached_verify_samples, pk.len(), sig.len());
    }
    for _ in 0..warmups() {
        black_box(pq_sign::ml_dsa_65_verify(black_box(&pk), black_box(MESSAGE), black_box(&sig))).unwrap();
        black_box(());
    }
    let mut samples = Vec::with_capacity(iterations());
    for _ in 0..iterations() {
        let cycle_start = cycles::read();
        let start = Instant::now();
        black_box(pq_sign::ml_dsa_65_verify(black_box(&pk), black_box(MESSAGE), black_box(&sig))).unwrap();
        black_box(());
        let cycle_sample = cycle_delta(cycle_start);
        let elapsed = start.elapsed().as_nanos();
        record_cycles(cycle_sample);
        samples.push(elapsed);
    }
    emit_operation_samples(
        "ml-dsa",
        "65",
        "verify",
        &samples,
        serde_json::json!({"public_key_bytes":pk.len(),"secret_key_bytes":ML_DSA_65_SECRET_KEY_LEN,"ciphertext_bytes":null,"signature_bytes":sig.len()}),
    );
}

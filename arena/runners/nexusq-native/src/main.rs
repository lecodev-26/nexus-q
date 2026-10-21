//! Arena runner for the experimental NEXUS-Q native backend. Same JSON schema, env
//! variables, per-operation Instant timing and nearest-rank statistics as the main
//! runner. x86-64 additionally records lfence/rdtsc ticks; other targets leave the
//! optional cycle sample array empty. Every operation follows the
//! FIPS contract used by the AWS-LC adapter: encaps/verify start from encoded
//! public-key bytes, decaps/sign from encoded secret-key bytes; no cached
//! expansion of A, t1 or H(pk).
use nexusq_native_backend::{mldsa65, mlkem768, mlkem1024};
use std::env;
use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MESSAGE: &[u8] = b"nexusq-pqc-arena-v1";

#[cfg(target_arch = "x86_64")]
#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: lfence; rdtsc; lfence has no memory effects.
    unsafe {
        core::arch::asm!("lfence", "rdtsc", "lfence", out("eax") lo, out("edx") hi, options(nostack, preserves_flags))
    };
    ((hi as u64) << 32) | lo as u64
}

#[inline]
fn cycles_now() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        Some(rdtsc())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

const fn cycle_counter_source() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64_tsc_ticks"
    } else {
        "unavailable_on_target"
    }
}

fn count(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn iterations() -> usize {
    count("NEXUSQ_ITERATIONS", 1000)
}
fn warmups() -> usize {
    count("NEXUSQ_WARMUPS", 100)
}

fn measure<F: FnMut()>(mut f: F) -> (Vec<u128>, Vec<u64>) {
    for _ in 0..warmups() {
        f();
    }
    let n = iterations();
    let (mut ns, mut cy) = (Vec::with_capacity(n), Vec::with_capacity(n));
    for _ in 0..n {
        let c0 = cycles_now();
        let t0 = Instant::now();
        f();
        let t1 = Instant::now();
        let c1 = cycles_now();
        ns.push(t1.duration_since(t0).as_nanos());
        if let (Some(start), Some(end)) = (c0, c1) {
            cy.push(end.wrapping_sub(start));
        }
    }
    (ns, cy)
}
fn median(s: &[u128]) -> u128 {
    let m = s.len() / 2;
    if s.len() % 2 == 0 {
        s[m - 1] + (s[m] - s[m - 1]) / 2
    } else {
        s[m]
    }
}
fn p95(s: &[u128]) -> u128 {
    let r = ((s.len() as f64) * 0.95).ceil() as usize;
    s[r.saturating_sub(1).min(s.len() - 1)]
}

fn emit(alg: &str, ps: &str, op: &str, (ns, cy): (Vec<u128>, Vec<u64>), sizes: serde_json::Value) {
    let mut sorted = ns.clone();
    sorted.sort_unstable();
    let mean = ns.iter().map(|x| *x as f64).sum::<f64>() / ns.len() as f64;
    let var = ns.iter().map(|x| (*x as f64 - mean).powi(2)).sum::<f64>() / ns.len() as f64;
    let med = median(&sorted);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let obj = serde_json::json!({
        "schema_version": 1,
        "run_id": format!("{}-{alg}-{ps}-{op}-{}", env::var("NEXUSQ_RUN_ID").unwrap_or_else(|_| "nexusq-native-local".into()), ns.len()),
        "implementation": {"id":"nexusq","version":env!("CARGO_PKG_VERSION"),
            "commit":env::var("NEXUSQ_GIT_COMMIT").unwrap_or_else(|_| "unknown".into()),
            "backend":{"name":"nexusq-native-backend",
                       "mlkem-native":"d1b2fe782888bdb761a50336012923180be7f502","mldsa-native":"834a90d5e846ffa1e1611bd24e160bb2e9b86d35",
                       "s2n-bignum":"4b5f8214e85b6b239077c278825b7fa9c2ab9cf5",
                       "keccak_x1":nexusq_native_backend::keccak_x1_backend(),
                       "avx2_bmi2_backend_active": nexusq_native_backend::native_backend_active()}},
        "algorithm": {"id":alg,"parameter_set":ps},
        "operation": op,
        "environment": {
            "target":format!("{}-{}", env::consts::ARCH, env::consts::OS), "os":env::consts::OS,
            "cpu":env::var("NEXUSQ_CPU").unwrap_or_else(|_| "unknown".into()),
            "cpu_features":env::var("NEXUSQ_CPU_FEATURES").unwrap_or_default().split(',').filter(|x| !x.is_empty()).collect::<Vec<_>>(),
            "compiler":"rustc+cc", "compiler_version":env::var("RUSTC_VERSION").unwrap_or_else(|_| "unknown".into()),
            "rng_source":if cfg!(feature = "aws-lc-rng") { "aws-lc-rand-bytes" } else { "getrandom-os" },
            "c_compiler":env::var("NEXUSQ_CC_VERSION").unwrap_or_else(|_| "unknown".into()),
            "rustc_verbose":env::var("NEXUSQ_RUSTC_VERBOSE").unwrap_or_else(|_| "unknown".into()),
            "cargo_lock_sha256":env::var("NEXUSQ_CARGO_LOCK_SHA256").unwrap_or_else(|_| "unknown".into()),
            "cpu_frequency_khz":env::var("NEXUSQ_CPU_FREQUENCY_KHZ").ok().and_then(|x| x.parse::<u64>().ok()),
            "cpu_governor":env::var("NEXUSQ_CPU_GOVERNOR").unwrap_or_else(|_| "unknown".into()),
            "run_order":env::var("NEXUSQ_RUN_ORDER").unwrap_or_else(|_| "unknown".into()),
            "optimization":"release lto=fat codegen-units=1; C -O3", "harness_version":"arena-v6-configurable-rng"
        },
        "measurement": {
            "iterations":ns.len(), "warmups":warmups(), "measurement_timestamp_unix_ns":ts, "latency_ns":med as f64,
            "throughput_ops_s":1e9 / med as f64, "memory_bytes":null,
            "measurement_method":"per-operation std::time::Instant; NEXUS-Q Rust API over mlkem-native/mldsa-native; median latency",
            "comparison_contract":"fips_operation_v1",
            "measurement_scope":"nexusq_native_backend_operation_from_encoded_keys",
            "samples_ns":ns,
            "statistics":{"sample_count":sorted.len(),"min_ns":sorted[0],"median_ns":med,"p95_ns":p95(&sorted),"stddev_ns":var.sqrt()},
            "cycle_counter_source":cycle_counter_source(), "samples_cycles":cy
        },
        "sizes": sizes
    });
    println!("{}", serde_json::to_string(&obj).unwrap());
}

macro_rules! kem_suite {
    ($m:ident, $ps:expr) => {{
        let (sk0, pk0) = $m::generate().expect("keygen");
        let (ct0, ss0) = pk0.encapsulate().expect("encaps");
        assert_eq!(sk0.decapsulate(&ct0).expect("decaps").as_bytes(), ss0.as_bytes(), "self-check");
        let sizes = serde_json::json!({"public_key_bytes":$m::PUBLIC_KEY_BYTES,"secret_key_bytes":$m::SECRET_KEY_BYTES,
                                       "ciphertext_bytes":$m::CIPHERTEXT_BYTES,"signature_bytes":null});
        emit("ml-kem", $ps, "keygen", measure(|| { black_box($m::generate().unwrap()); }), sizes.clone());
        // Public key as encoded bytes; the native API re-validates and re-hashes it on every call (FIPS 203).
        let pk_bytes = pk0.0;
        let pk = $m::EncapsulationKey::from_bytes(&pk_bytes).unwrap();
        let mut last_ct = ct0.clone();
        emit("ml-kem", $ps, "encaps", measure(|| { let (c, s) = black_box(&pk).encapsulate().unwrap(); black_box(&s); last_ct = c; }), sizes.clone());
        let sk = $m::DecapsulationKey::from_bytes(sk0.as_bytes()).unwrap();
        let ct = last_ct;
        emit("ml-kem", $ps, "decaps", measure(|| { black_box(black_box(&sk).decapsulate(black_box(&ct)).unwrap()); }), sizes);
    }};
}

fn main() {
    kem_suite!(mlkem768, "768");
    kem_suite!(mlkem1024, "1024");
    let sizes = serde_json::json!({"public_key_bytes":mldsa65::PUBLIC_KEY_BYTES,"secret_key_bytes":mldsa65::SECRET_KEY_BYTES,
                                   "ciphertext_bytes":null,"signature_bytes":mldsa65::SIGNATURE_BYTES});
    emit(
        "ml-dsa",
        "65",
        "keygen",
        measure(|| {
            black_box(mldsa65::generate().unwrap());
        }),
        sizes.clone(),
    );
    // One key per round, hedged (randomized) signing with empty context: the AWS-LC adapter's protocol.
    let (sk, pk) = mldsa65::generate().unwrap();
    let mut sig = sk.sign(MESSAGE, b"").unwrap();
    pk.verify(MESSAGE, b"", &sig.0).expect("self-check");
    emit(
        "ml-dsa",
        "65",
        "sign",
        measure(|| {
            sig = black_box(&sk).sign(black_box(MESSAGE), b"").unwrap();
        }),
        sizes.clone(),
    );
    let pk = mldsa65::VerifyingKey::from_bytes(&pk.0).unwrap();
    emit(
        "ml-dsa",
        "65",
        "verify",
        measure(|| {
            black_box(black_box(&pk).verify(black_box(MESSAGE), b"", black_box(&sig.0))).unwrap();
        }),
        sizes,
    );
}

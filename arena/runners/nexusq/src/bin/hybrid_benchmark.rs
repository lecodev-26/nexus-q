use nexusq_core::crypto::kem::hybrid;
use std::hint::black_box;
use std::time::Instant;

const SAMPLES: usize = 1000;
const WARMUPS: usize = 100;

fn percentile(sorted: &[u128], p: usize) -> u128 {
    let idx = ((sorted.len() - 1) * p) / 100;
    sorted[idx]
}

fn stats(mut values: Vec<u128>) -> (u128, u128, u128, u128) {
    values.sort_unstable();
    let sum: u128 = values.iter().sum();
    (
        sum / values.len() as u128,
        percentile(&values, 50),
        percentile(&values, 95),
        percentile(&values, 99),
    )
}

fn main() {
    let pair = hybrid::generate();
    let public = pair.public_key_bytes();

    for _ in 0..WARMUPS {
        let (ct, _) = hybrid::encapsulate(&public).expect("hybrid encapsulation");
        black_box(hybrid::decapsulate(&pair, &ct).expect("hybrid decapsulation"));
    }

    let mut enc = Vec::with_capacity(SAMPLES);
    let mut dec = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let (ct, ss) = hybrid::encapsulate(&public).expect("hybrid encapsulation");
        black_box(ss);
        enc.push(start.elapsed().as_nanos());

        let start = Instant::now();
        black_box(hybrid::decapsulate(&pair, &ct).expect("hybrid decapsulation"));
        dec.push(start.elapsed().as_nanos());
    }

    let (enc_mean, enc_p50, enc_p95, enc_p99) = stats(enc);
    let (dec_mean, dec_p50, dec_p95, dec_p99) = stats(dec);
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("model name")
                    .and_then(|v| v.strip_prefix(':'))
                    .map(str::trim)
                    .map(str::to_owned)
            })
        })
        .unwrap_or_else(|| "unknown".into());

    println!("schema=v1");
    println!("implementation=nexusq-production-hybrid-ml-kem-768-x25519");
    println!("workload=encaps+decaps");
    println!("samples={SAMPLES}");
    println!("warmups={WARMUPS}");
    println!("profile=release");
    println!("cpu={cpu}");
    println!(
        "rustc={}",
        std::env::var("NEXUSQ_RUSTC_VERSION").unwrap_or_else(|_| "unknown".into())
    );
    println!("encaps_mean_ns={enc_mean}");
    println!("encaps_p50_ns={enc_p50}");
    println!("encaps_p95_ns={enc_p95}");
    println!("encaps_p99_ns={enc_p99}");
    println!("decaps_mean_ns={dec_mean}");
    println!("decaps_p50_ns={dec_p50}");
    println!("decaps_p95_ns={dec_p95}");
    println!("decaps_p99_ns={dec_p99}");
}

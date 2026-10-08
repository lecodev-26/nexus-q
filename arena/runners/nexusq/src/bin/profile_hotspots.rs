use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, MlKem1024};
use nexusq_core::crypto::{kem::ml_kem_768, pq_sign};
use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

struct CountingAllocator;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static DEALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCS.fetch_add(1, Ordering::Relaxed);
        DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const ITERS: usize = 2000;
const MESSAGE: &[u8] = b"nexusq-v2-profile-message";

fn reset() {
    ALLOCS.store(0, Ordering::Relaxed);
    DEALLOCS.store(0, Ordering::Relaxed);
    REALLOCS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    DEALLOC_BYTES.store(0, Ordering::Relaxed);
}

fn report(name: &str, elapsed_ns: u128) {
    println!(
        "{name}\titerations={ITERS}\tns_per_op={:.1}\tallocs_per_op={:.2}\treallocs_per_op={:.2}\tallocated_bytes_per_op={:.1}\tdeallocated_bytes_per_op={:.1}",
        elapsed_ns as f64 / ITERS as f64,
        ALLOCS.load(Ordering::Relaxed) as f64 / ITERS as f64,
        REALLOCS.load(Ordering::Relaxed) as f64 / ITERS as f64,
        ALLOC_BYTES.load(Ordering::Relaxed) as f64 / ITERS as f64,
        DEALLOC_BYTES.load(Ordering::Relaxed) as f64 / ITERS as f64,
    );
}

fn main() {
    let workload = env::args().nth(1).expect("workload required");
    match workload.as_str() {
        "ml-kem-768-keygen" => {
            for _ in 0..20 {
                black_box(ml_kem_768::generate());
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(ml_kem_768::generate());
            }
            report(&workload, t.elapsed().as_nanos());
        }
        "ml-kem-768-encaps" => {
            let (_, pk) = ml_kem_768::generate();
            for _ in 0..20 {
                black_box(ml_kem_768::encapsulate(&pk));
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(ml_kem_768::encapsulate(&pk));
            }
            report(&workload, t.elapsed().as_nanos());
        }
        "ml-kem-768-decaps" => {
            let (sk, pk) = ml_kem_768::generate();
            let (ct, _) = ml_kem_768::encapsulate(&pk);
            for _ in 0..20 {
                black_box(ml_kem_768::decapsulate(&sk, &ct)).unwrap();
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(ml_kem_768::decapsulate(&sk, &ct)).unwrap();
            }
            report(&workload, t.elapsed().as_nanos());
        }
        "ml-kem-1024-keygen" => {
            for _ in 0..20 {
                black_box(MlKem1024::generate_keypair());
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(MlKem1024::generate_keypair());
            }
            report(&workload, t.elapsed().as_nanos());
        }
        "ml-kem-1024-encaps" => {
            let (_, pk): (DecapsulationKey1024, EncapsulationKey1024) =
                MlKem1024::generate_keypair();
            for _ in 0..20 {
                black_box(pk.encapsulate());
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(pk.encapsulate());
            }
            report(&workload, t.elapsed().as_nanos());
        }
        "ml-kem-1024-decaps" => {
            let (sk, pk): (DecapsulationKey1024, EncapsulationKey1024) =
                MlKem1024::generate_keypair();
            let (ct, _) = pk.encapsulate();
            for _ in 0..20 {
                black_box(sk.decapsulate(&ct));
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(sk.decapsulate(&ct));
            }
            report(&workload, t.elapsed().as_nanos());
        }
        "ml-dsa-65-keygen" => {
            for _ in 0..20 {
                black_box(pq_sign::MlDsa65KeyPair::generate());
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(pq_sign::MlDsa65KeyPair::generate());
            }
            report(&workload, t.elapsed().as_nanos());
        }
        "ml-dsa-65-sign" => {
            let key = pq_sign::MlDsa65KeyPair::generate();
            for _ in 0..20 {
                black_box(key.sign(MESSAGE));
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(key.sign(MESSAGE));
            }
            report(&workload, t.elapsed().as_nanos());
        }
        "ml-dsa-65-verify" => {
            let key = pq_sign::MlDsa65KeyPair::generate();
            let pk = key.public_key();
            let sig = key.sign(MESSAGE);
            for _ in 0..20 {
                black_box(pq_sign::ml_dsa_65_verify(&pk, MESSAGE, &sig)).unwrap();
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(pq_sign::ml_dsa_65_verify(&pk, MESSAGE, &sig)).unwrap();
            }
            report(&workload, t.elapsed().as_nanos());
        }
        "ml-dsa-65-verify-cached" => {
            let key = pq_sign::MlDsa65KeyPair::generate();
            let pk = key.public_key();
            let verifier = pq_sign::MlDsa65VerifyingKey::from_public_key(&pk).unwrap();
            let sig = key.sign(MESSAGE);
            for _ in 0..20 {
                black_box(verifier.verify(MESSAGE, &sig)).unwrap();
            }
            reset();
            let t = Instant::now();
            for _ in 0..ITERS {
                black_box(verifier.verify(MESSAGE, &sig)).unwrap();
            }
            report(&workload, t.elapsed().as_nanos());
        }
        _ => panic!("unknown workload: {workload}"),
    }
}

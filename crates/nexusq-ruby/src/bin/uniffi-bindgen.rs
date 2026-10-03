//! Binary that generates UniFFI bindings for this crate.
//!
//! Run with:
//!
//!     cargo run -p nexusq-ruby --bin uniffi-bindgen -- \\
//!         generate --library path/to/libnexusq_ruby.so \\
//!         --language ruby --out-dir bindings/ruby

fn main() {
    uniffi::uniffi_bindgen_main();
}

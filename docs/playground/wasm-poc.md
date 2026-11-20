# NEXUS-Q Playground — WebAssembly proof of concept

The `nexusq-wasm` crate is an isolated browser bridge over the existing
`nexusq-core` ML-DSA-65 and ML-KEM-768 APIs. It does not change the server,
CLI, Vault, or existing website.

## Security boundaries

- Browser randomness is provided by `getrandom`'s `wasm_js` backend, which
  delegates to the browser's Web Crypto implementation. There is no fallback
  to `Math.random()`.
- ML-DSA and ML-KEM private key objects remain owned by Rust values in WASM;
  the bridge intentionally has no private-key export method.
- The ML-KEM shared secret is exposed only for an educational local
  interoperability demonstration. Applications must not log or persist it.
- WebAssembly does not by itself guarantee secure memory erasure, protect
  against malicious browser extensions, or make this code independently
  audited. Do not use this proof of concept to protect production secrets.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo check -p nexusq-wasm --target wasm32-unknown-unknown --locked
cargo test -p nexusq-wasm --locked
```

A production package still needs a reviewed `wasm-bindgen`/`wasm-pack` build,
versioned JS bindings, browser integration tests, CSP review, memory-lifecycle
review, and cross-browser verification.

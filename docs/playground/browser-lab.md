# NEXUS-Q browser Playground

The static browser experience lives in `site/playground/`. It uses the `nexusq-wasm` Rust crate for ML-DSA-65 and ML-KEM-768 operations. The browser package is generated into `site/playground/pkg/` and is intentionally not hand-written.

## Build the browser package

Install a Rust toolchain with the `wasm32-unknown-unknown` target and `wasm-pack`, then run:

```sh
./scripts/build-playground-wasm.sh
```

The GitHub Actions workflow `NEXUS-Q Playground WASM` performs the same build and uploads `nexusq-playground-wasm` as a short-lived workflow artifact. Download that artifact into `site/playground/pkg/` when a local environment cannot compile the WASM target itself.

## Preview the static site

From the repository root, serve the `site/` directory with any static HTTP server. For example:

```sh
python3 -m http.server 8000 --directory site
```

Then open `http://localhost:8000/playground/`. The WASM-powered labs require the generated package; the password generator and learning content remain available without it.

## Security boundaries

- ML-DSA-65 and ML-KEM-768 are invoked in the browser through the Rust/WASM bridge.
- Private key objects are not exported by the browser API.
- The password generator uses `crypto.getRandomValues()` with rejection sampling; it does not use `Math.random()`.
- The ML-KEM educational flow briefly copies the shared secret into JavaScript memory to compare encapsulation and decapsulation. The UI clears those temporary typed-array copies after comparison. Do not use the demonstration secret as a production session key.
- No account, server-side key storage, analytics event, or secret upload is implemented by this Playground.
- This is an educational proof of concept, not an independently audited or certified cryptographic product.

# nexusq-x509

RFC 5280 X.509 certificate issuance using NexusQ's post-quantum signature implementations.

## Current capabilities

- Standards-based DER encoding and PEM serialization through RustCrypto `x509-cert` / `der`.
- Self-signed CA roots using all supported ML-DSA parameter sets and SLH-DSA parameter sets.
- ML-DSA-65 subordinate CA certificates signed by a separate ML-DSA-65 issuer key.
- A generic `issue_certificate` entry point for custom RFC 5280 profiles and signers that implement the compatible `signature` / SPKI traits.
- `RevocationUrls` and `issue_ml_dsa_subordinate_ca_with_revocation_urls` to advertise HTTPS OCSP and CRL locations in Authority Information Access and CRL Distribution Points extensions.
- An opt-in `experimental-composite` feature for the draft ML-DSA-65 + Ed25519 profile (OID `1.3.6.1.5.5.7.6.48`), explicitly marked experimental because the LAMPS specification is not a final RFC.
- Tests for DER and PEM round trips, valid signatures, malformed input, and modified signatures.

The `x509-cert` builder supplies the certificate structure, CA extensions, and ASN.1 encoding. ML-DSA algorithm identifiers follow [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html); SLH-DSA identifiers follow [RFC 9909](https://www.rfc-editor.org/rfc/rfc9909.html).

## Example

```rust,no_run
use core::{str::FromStr, time::Duration};
use nexusq_x509::ml_dsa::{Generate, MlDsa65, SigningKey};
use nexusq_x509::x509_cert::{name::Name, serial_number::SerialNumber};
use nexusq_x509::{certificate_to_pem, issue_self_signed_ml_dsa65_root, validity_for};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = SigningKey::<MlDsa65>::generate();
    let subject = Name::from_str("CN=NexusQ Root,O=NexusQ,C=US")?;
    let cert = issue_self_signed_ml_dsa65_root(
        subject,
        SerialNumber::from(1u32),
        validity_for(Duration::from_secs(365 * 24 * 60 * 60))?,
        &key,
    )?;
    std::fs::write("nexusq-root.pem", certificate_to_pem(&cert)?)?;
    Ok(())
}
```

## Interoperability status

Local tests cover DER/PEM parsing, signature verification, malformed inputs, and modified signatures. External checks were run on 2026-10-21; the reproducible harness is in [`interop/`](interop/README.md):

- OpenSSL 3.5.9 verifies the self-signed ML-DSA-65 and SLH-DSA roots.
- Bouncy Castle 1.86 verifies the self-signed ML-DSA-65 and SLH-DSA roots.
- Bouncy Castle 1.86 verifies the experimental composite ML-DSA-65 + Ed25519 root.
- OpenSSL 3.5.9 does not recognize the draft composite public-key algorithm; that profile remains feature-gated and is not broadly interoperable.

ML-DSA algorithm identifiers follow [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html); SLH-DSA identifiers follow [RFC 9909](https://www.rfc-editor.org/rfc/rfc9909.html). The experimental composite profile follows [LAMPS draft-19](https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-19.html), which is an Internet-Draft and must not be treated as a finalized standard. Its feature is disabled by default.

## Security notes

- The issuer signer must be authorized for the chosen profile; the generic API cannot make that policy decision for the caller.
- Certificate issuance is not a full path validator or a complete CA policy engine.
- Keep signing keys protected; this crate does not persist or export private keys.

# NexusQ OCSP responder and CRL publisher

This crate provides a small RFC 6960/RFC 5280 service layer for the NexusQ PKI work:

- DER OCSP requests and signed `application/ocsp-response` output using ML-DSA-65.
- Distinct `good`, `revoked`, and `unknown` responses; a missing serial is never treated as good.
- SHA-1 and SHA-256 CertID issuer hashes, bounded request size/count, issuer name/key hash checks, nonce echo, and rejection of signed requests or unsupported critical request extensions.
- A signed DER X.509 CRL with monotonically versioned CRL numbers, `thisUpdate`/`nextUpdate`, and revocation-reason extensions.
- An Axum router exposing `POST /ocsp` and `GET /crl`, with response content types and a 1 MiB request-body limit.

## Mounting the routes

Construct the service with the issuer certificate, its matching ML-DSA-65 signing key, a populated `RevocationStore`, and the initial CRL number. Mount `Arc::new(service).router()` into the host application or serve it with Axum. The key must be authorized for the issuer certificate and must remain in the configured key provider; this crate never serializes private key material.

Leaf/subordinate certificates should advertise the corresponding OCSP and CRL locations. `nexusq-x509::RevocationUrls` validates HTTPS locations, and `issue_ml_dsa_subordinate_ca_with_revocation_urls` adds Authority Information Access and CRL Distribution Points extensions.

## Operational boundaries

The provided `RevocationStore` is intentionally an in-memory reference store. A production deployment must back it with durable, transactional CA state and replicate it before enabling HA; otherwise a restart loses status information. CRL numbers must be persisted and never reused across restarts, so supply the persisted current number when constructing the service. The router does not start a network listener by itself.

The handler rejects malformed/unsupported requests and caps request bodies at 1 MiB and certificate IDs at 16 per request. The regression tests cover all three statuses, wrong-issuer rejection, response signature verification, CRL encoding, and HTTP content types. The signing path is exercised by unit tests; deployments should benchmark their target hardware and keep the p95 response latency below the issue target of 300 ms before rollout.

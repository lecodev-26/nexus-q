# NexusQ certificate enrollment

This crate provides policy-controlled ML-DSA-65 PKCS#10 CSR validation and certificate issuance with three protocol adapters:

- **ACME issuance profile:** `GET /acme/directory`, `HEAD /acme/new-nonce`, account registration, DNS orders, HTTP-01/DNS-01 authorization objects, challenge validation through a mandatory host-supplied validator, finalization and PEM certificate-chain retrieval. ACME account JWS supports ES256 and RS256; the requested certificate CSR must be ML-DSA-65. The end-to-end test uses a synthetic ES256 client and a test-only validator. Certbot has not been tested, and clients unable to generate an ML-DSA-65 CSR are not compatible with this selected certificate profile.
- **EST:** `POST /.well-known/est/simpleenroll`, `GET /.well-known/est/cacerts`, and `GET /.well-known/est/csrattrs`. `simpleenroll` requires HTTP Basic authentication, expects RFC 7030 base64-encoded PKCS#10, and returns a certs-only CMS SignedData response containing the issued certificate and issuer certificate.
- **CMPv2:** `POST /cmp` supports the P10CR message body with PBM/HMAC-SHA-256 message protection. PBM salt length and iteration count are bounded, the senderKID selects a configured shared secret, the sender name is bound to `CN=<senderKID>`, and the recipient must match the configured CA. CRMF `ir`/`cr` messages and non-PBM protection are rejected rather than downgraded.

All three adapters use the same CSR validator and policy engine. It verifies the CSR signature and algorithm, permits only DNS Subject Alternative Names, enforces global or per-principal DNS suffix authorization, caps leaf validity at both policy and issuer expiry, emits a non-CA leaf profile with Key Usage/EKU/SKI/AKI, and can advertise HTTPS OCSP/CRL locations. The service applies a rolling per-principal enrollment rate limit and records request hashes and outcomes without logging CSR bodies or private key material.

## Deployment boundaries

- Mount the router(s) in a host application; these APIs do not start a network listener. Serve them behind HTTPS and configure the public ACME base URL exactly as seen by clients.
- Supply a real ACME challenge validator that checks public HTTP-01/DNS-01 state. The router intentionally has no permissive default validator.
- Accounts, orders, challenges, nonces, rate-limit buckets, serial allocation and audit events are currently in-memory. A production deployment must persist/replicate these before HA or restart-safe use; configure a durable serial counter and audit sink. The CA key remains in memory for this library instance and must be supplied by the configured key provider.
- SCEP was assessed and deliberately left unregistered; see [`docs/scep-assessment.md`](docs/scep-assessment.md).

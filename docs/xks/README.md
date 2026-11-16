# NEXUS-Q XKS Proxy

`nexusq-xks-proxy` is the standalone AWS KMS External Key Store (XKS) v1
HTTP protocol crate. It is deliberately separate from `nexusq-core`, the vault
CBOR envelope API, and Floci's KMS control plane.

## Scope

The router exposes the four AWS XKS v1 POST operations below a configured path
ending in `/kms/xks/v1`:

- `POST /health`
- `POST /keys/{externalKeyId}/metadata`
- `POST /keys/{externalKeyId}/encrypt`
- `POST /keys/{externalKeyId}/decrypt`

The service implements AWS SigV4 request verification (`host;x-amz-date`,
service `kms-xks-proxy`), a five-minute timestamp window, JSON transport,
request bounds, Base64 and AES-GCM field validation, error-name mapping, and
SHA-256 CDIV computation. For CDIV requests it computes the value before
performing the required encrypt/decrypt round-trip.

## Key-manager boundary

Integrators provide an `XksKeyProvider`. Its operations receive an external key
identifier and opaque plaintext/ciphertext inputs; its contract requires the
implementation to execute AES-GCM inside the external key manager and never
export key material to this process. The existing NEXUS-Q `Session::encrypt`
and `Session::decrypt` APIs are intentionally not used: those APIs process the
NEXUS-Q CBOR envelope, not the raw AES-GCM XKS wire protocol.

The crate includes a PKCS#11 adapter backed by `nexusq-hsm`. It provisions
AES-256 secret keys with `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, and
only encrypt/decrypt usage enabled. The adapter accepts an explicit allow-list
from XKS external key IDs to persisted PKCS#11 key references; requests never
create or delete keys. AES-GCM operations execute through PKCS#11 and key bytes
are never read into the proxy process. The adapter does not currently support
non-empty `ciphertextMetadata` or dynamic per-key disablement.

## Running the service

The `nexusq-xks-proxy` binary reads a protected JSON file (recommended mode
`0600`) from `NEXUSQ_XKS_CONFIG`. It contains `uriPath`, `accessKeyId`,
`secretAccessKey`, optional `additionalCredentials` (at most one additional pair for rotation), `pkcs11Module`, `pkcs11SlotIndex`, `pkcs11Pin`,
`ekmVendor`, `ekmModel`, a dedicated `healthCheckKeyRef`, and a `keys` array
containing `{ externalKeyId, keyRef }` mappings. Each reference is the
serialized `Pkcs11AesKeyRef` returned by the HSM provisioning API. The health
key is not exposed as an external KMS key and must be provisioned separately. Generate keys separately with
`Pkcs11Provider::generate_aes256_gcm_key`, persist the returned serialized
`Pkcs11AesKeyRef`, then configure the external ID mapping. Do not provision keys
on demand from AWS requests.

The HSM adapter performs a deep AES-GCM round-trip with the dedicated non-exportable health-check key at startup and refreshes the cached result every 30 seconds; AWS KMS receives a cached result no older than one minute. This avoids requiring the proxy process to create or delete keys during routine health checks.

The default bind is `127.0.0.1:9443`. Configure the load balancer TCP check or HTTP GET check against the unauthenticated `/healthz` route under the configured URI path; it returns 503 when the HSM is unavailable. For a non-loopback bind, the operator must
set `NEXUSQ_XKS_TRUSTED_TLS_TERMINATION=1` and place the service behind a
trusted TLS 1.2+ terminator with an AWS-trusted certificate. The application
listener itself is HTTP; it does not implement TLS.

## Deployment requirements

The router is transport-agnostic. Production deployments MUST terminate HTTPS
with TLS 1.2 or later and an AWS-trusted server certificate. Do not require
mTLS. Store SigV4 credentials in a secret manager, restrict access to them,
rotate credentials by loading both active SigV4 key pairs simultaneously, updating KMS, and then removing the old pair. Changes to the file require a controlled process restart/rolling deployment; live hot-reload is not yet supported. Log only operation names, external key IDs, and KMS request correlation IDs. Never log request bodies, plaintext, decrypted data, or secret values. The library does not silently select a software-key fallback.

## AWS compatibility status

This crate is a protocol implementation component, not a claim of end-to-end
AWS XKS compatibility. Compatibility requires deployment TLS, the AWS XKS test client, negative-case
coverage, and interoperability against a compatible KMS implementation. The
PKCS#11 adapter has an optional SoftHSM integration test gated by the existing
`softhsm-tests` feature and the repository SoftHSM setup script. Those gates must be
reported separately from ordinary CI success.

## References

- [AWS XKS Proxy API specification](https://github.com/aws/aws-kms-xksproxy-api-spec/blob/main/xks_proxy_api_spec.md)
- [AWS KMS External Key Stores](https://docs.aws.amazon.com/kms/latest/developerguide/keystore-external.html)
- [ADR 0007 — XKS proxy architecture](../adr/0007-xks-proxy-architecture.md)

Provision an HSM key and emit one mapping entry for the service configuration
with `cargo run -p nexusq-xks-proxy --example provision-aes-key`. Set
`NEXUSQ_PKCS11_MODULE`, `NEXUSQ_PKCS11_SLOT_INDEX`, `NEXUSQ_PKCS11_PIN`,
`NEXUSQ_XKS_KEY_LABEL`, and `NEXUSQ_XKS_EXTERNAL_KEY_ID` in the provisioning
environment. The output contains only the opaque PKCS#11 reference and the
external identifier, never key material or the PIN.

The `XKS PKCS#11 HSM Integration` GitHub Actions workflow provisions an
isolated SoftHSM token, checks non-extractable AES-256-GCM behavior, starts the
proxy, and runs the official AWS XKS proxy test client against it. This is
protocol conformance against the AWS sample client; it is not a claim of
interoperability with the AWS KMS service or Floci. Those external integration
checks remain separate release gates.

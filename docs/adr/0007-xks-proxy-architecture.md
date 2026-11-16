# ADR 0007 — AWS KMS XKS proxy architecture

- **Status:** Proposed
- **Date:** 2026-11-16
- **Phase:** External key management / integration

## Context

NEXUS-Q is evaluating an interoperable external-key integration with Floci.
The upstream discussion recommended the standard AWS KMS External Key Store
(XKS) model rather than a Floci-specific protocol. Floci already implements
KMS operations and supports `Origin=EXTERNAL` for imported key material, but
imported key material is not the same feature as
`Origin=EXTERNAL_KEY_STORE`.

AWS XKS separates the KMS control plane from the external key manager's data
plane. AWS KMS (or a compatible KMS implementation such as Floci) manages the
Custom Key Store and KMS key resources. The external XKS proxy exposes the
standard HTTPS API through which the KMS forwards cryptographic operations to
the external key manager.

NEXUS-Q's current architecture is library-first and layered. Consumers and
services belong in L4 and must use public interfaces; cryptographic
primitives, vault lifecycle and policy belong in L3; hardware and key
backends are behind provider traits. An XKS HTTP endpoint is an integration
service, not a new primitive and not a reason to place HTTP, AWS protocol
handling or Floci-specific behavior inside the core vault.

There is also a concrete API mismatch to resolve before implementation:

- `Session::encrypt` and `Session::decrypt` operate on NEXUS-Q's CBOR envelope
  format. They are not the raw AES-256-GCM operations and response format
  required by XKS.
- The current `KeyProvider` trait supports key generation, signing, public
  key access, destruction and metadata. It does not expose AEAD encrypt and
  decrypt operations against a non-exportable key handle.
- The low-level AEAD helpers accept raw key bytes. Passing key material into
  the HTTP proxy would undermine the intended non-exportable-key boundary.

Therefore, neither the vault envelope API nor raw key extraction is an
acceptable shortcut for XKS integration.

## Decision

### 1. Implement the XKS proxy as an independent L4 service

Create a dedicated workspace component, provisionally named
`nexusq-xks-proxy` under `crates/nexusq-xks-proxy`.

The component owns:

- AWS XKS HTTP request and response parsing;
- the `/kms/xks/v1` route surface;
- request authentication and protocol validation;
- conversion between XKS wire types and a provider-neutral operation
  interface;
- health reporting, bounded request handling and safe operational logging.

It must not be embedded in `nexusq-core`, `nexusq-vault`, or the core crypto
primitive modules. It must not depend on Floci internals or introduce a
NEXUS-Q-specific wire protocol.

### 2. Implement the XKS v1 data-plane contract, not the KMS control plane

The proxy will implement the four XKS v1 operations defined by AWS:

1. `GetHealthStatus`
2. `GetKeyMetadata`
3. `Encrypt`
4. `Decrypt`

The proxy will not implement `CreateCustomKeyStore`,
`DescribeCustomKeyStores`, `ConnectCustomKeyStore`,
`DisconnectCustomKeyStore`, `UpdateCustomKeyStore`, `DeleteCustomKeyStore`,
or KMS key creation. Those are responsibilities of the KMS control plane
(e.g. Floci), not the XKS proxy.

`GenerateDataKey` is not a separate XKS proxy endpoint. Higher-level KMS
operations are composed by the KMS using the XKS operations in the standard
protocol.

### 3. Put cryptographic execution behind a provider-neutral boundary

The proxy will depend on a narrow `XksKeyProvider`-style interface with
operations equivalent to:

- resolve metadata for an externally managed key identifier;
- encrypt using that key and the exact XKS AES-GCM inputs;
- decrypt using that key and the exact XKS AES-GCM inputs;
- report provider health.

The interface is an architectural port, not permission to export key bytes.
Implementations must perform cryptographic operations inside the external
key manager or protected backend and return only the protocol-required
results. The external key identifier must be mapped through an explicit
configured/authorized namespace; the proxy must not accept arbitrary backend
object references from untrusted callers.

A future NEXUS-Q adapter may use an HSM or another protected backend, but it
must not claim compatibility merely by wrapping `Session::encrypt` or by
calling raw-key AEAD helpers after extracting a key. If the existing public
backend API cannot perform AES-GCM with a non-exportable key handle, a
separate, reviewed API/trait extension is required before that adapter is
implemented. That extension must preserve the core's layering and policy
boundaries.

### 4. Follow the AWS XKS v1 cryptographic and transport requirements

The implementation must follow the current AWS XKS Proxy API specification,
including its complete schemas and validation rules, rather than treating
four route names as sufficient compliance.

At minimum, the design and implementation must preserve these constraints:

- XKS v1 key material is a 256-bit symmetric AES key using
  `SYMMETRIC_DEFAULT` and AES-GCM.
- The proxy uses HTTPS with TLS 1.2 or later and the standard
  `/kms/xks/v1` path suffix.
- Proxy authentication follows the XKS SigV4 requirements. The design must
  not require mutual TLS; mTLS is not a valid compatibility dependency for
  newly created XKS stores under current AWS guidance.
- AES-GCM IV, authentication tag, ciphertext and associated metadata are
  handled exactly as specified. Required ciphertext-dependency validation
  (including CDIV requirements) must not be omitted.
- The external key manager remains authoritative for external key material.
  The proxy must not persist, log or return raw key material.
- Health checks, timeouts, error mapping, request-size limits and concurrency
  controls must be explicit. No unbounded retries may turn a failed or
  ambiguous cryptographic operation into unsafe behavior.

### 5. Keep Floci integration separate

Floci's responsibility is to implement the KMS Custom Key Store control-plane
behavior and route KMS cryptographic operations to a configured XKS proxy.
NEXUS-Q's responsibility is to provide the standards-based XKS proxy and its
backend integration. Neither project should require private extensions to
the other's protocol.

## Security requirements

- Never expose or log external key bytes, plaintext, decrypted data, SigV4
  credentials, authorization headers or secret configuration values.
- Authenticate every operation according to the AWS XKS specification and
  reject malformed, unauthorized, unknown-key and unsupported-algorithm
  requests closed by default.
- Bind every operation to an explicitly configured external key identifier;
  do not permit caller-controlled path traversal or arbitrary backend
  identifier resolution.
- Keep key material non-exportable where the backend supports it. The proxy
  must not introduce a software copy of an HSM-held key as an integration
  shortcut.
- Use constant-time authentication-tag verification provided by a
  maintained cryptographic implementation. Do not invent cryptographic
  constructions or alter the AWS wire format.
- Ensure logs and audit events contain operation metadata and correlation
  identifiers only, never secret or plaintext-bearing payloads.
- Treat provider errors and health failures as fail-closed; do not silently
  fall back to a different key, algorithm, or local software key.
- Document the trust boundary between the KMS, proxy process, network,
  external key manager and any HSM.

## Scope boundaries

**In scope:**

- A standalone, standards-based XKS v1 proxy service.
- A provider abstraction suitable for HSM-backed or other external key
  managers.
- Exact AWS wire compatibility, authentication, validation and error
  behavior.
- Operational health, timeouts, bounded concurrency and security logging.

**Out of scope for this ADR:**

- Implementing AWS KMS Custom Key Store control-plane APIs in NEXUS-Q.
- Implementing an XKS proxy inside Floci.
- A Floci-specific protocol or any NEXUS-Q-specific replacement for XKS.
- Replacing or changing the existing `Origin=EXTERNAL` imported-key flow.
- Adding a `GenerateDataKey` proxy endpoint.
- Claiming full AWS XKS compatibility before protocol conformance and
  interoperability evidence exists.
- Selecting a specific HSM vendor, PKCS#11 deployment, cloud key manager or
  production topology.

## Consequences

**Positive:**

- XKS remains an integration service and does not contaminate the core vault
  or cryptographic primitive layers with HTTP/AWS concerns.
- The wire protocol is reusable by AWS KMS and compatible implementations
  such as Floci.
- The provider boundary allows HSM-backed operations without exposing key
  material to the proxy.
- The mismatch between today's vault-envelope API and XKS raw AES-GCM
  semantics is explicit before implementation begins.

**Negative:**

- A dedicated service crate and provider adapter must be maintained.
- The current `KeyProvider` API is insufficient for XKS AEAD operations;
  a separately reviewed interface extension or backend-specific adapter
  will be needed.
- Full compatibility requires conformance and interoperability testing
  against the AWS specification and compatible KMS implementations.

**Neutral:**

- Floci can implement its Custom Key Store control plane independently.
- Existing imported external key material and vault envelope behavior remain
  unchanged.

## Implementation gates

Implementation must be split into reviewable steps and must not begin by
changing the core vault API implicitly:

1. Agree on this architecture and the provider contract.
2. Specify the provider interface and the non-exportable-key integration
   boundary, including whether a core/backend trait extension is necessary.
3. Implement and validate XKS wire types, SigV4 authentication and protocol
   error mapping.
4. Implement the four XKS v1 operations against a test provider.
5. Add a protected-backend adapter without exposing key bytes.
6. Run the AWS XKS test client and interoperability tests against Floci (or
   another compatible KMS implementation), then document the exact verified
   compatibility scope.

No production-readiness or full-XKS-support claim is valid until the
cryptographic, protocol, authentication, negative-case and interoperability
gates have evidence.

## References

- `docs/ARCHITECTURE.md` — NEXUS-Q layers and dependency rules.
- `crates/nexusq-core/src/vault/container.rs` — current vault envelope API.
- `crates/nexusq-core/src/hardware/key_provider.rs` — current hardware key
  provider contract.
- `crates/nexusq-core/src/crypto/aead.rs` — low-level AEAD helpers and their
  raw-key boundary.
- [AWS KMS XKS Proxy API specification](https://github.com/aws/aws-kms-xksproxy-api-spec/blob/main/xks_proxy_api_spec.md).
- [AWS KMS External Key Stores](https://docs.aws.amazon.com/kms/latest/developerguide/keystore-external.html).
- [AWS sample XKS proxy](https://github.com/aws-samples/aws-kms-xks-proxy).
- [AWS XKS proxy test client](https://github.com/aws-samples/aws-kms-xksproxy-test-client).
- [Floci upstream XKS discussion](https://github.com/floci-io/floci/discussions/7495#discussioncomment-19646201).
- [Floci XKS exploration issue](https://github.com/floci-io/floci/issues/8555).

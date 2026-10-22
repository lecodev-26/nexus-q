# NexusQ RFC 3161 Timestamp Authority

`nexusq-tsa` accepts DER-encoded RFC 3161 `TimeStampReq` messages and returns a DER-encoded CMS `ContentInfo` `TimeStampToken` containing `TSTInfo`, signed with ML-DSA-65.

## Configuration

- Provide a dedicated v3 TSA certificate and the matching ML-DSA-65 signing key. The certificate must be currently valid, include critical `extendedKeyUsage` containing only `id-kp-timeStamping`, include `keyUsage` with `digitalSignature`, and have `basicConstraints` with `CA=FALSE`. The subject public key must match the configured signing key.
- Select a policy OID and a non-zero first serial number.
- Prefer `TimestampAuthority::with_time_source` with an audited, synchronized time source. The authority rejects time moving backwards and refuses to issue outside the certificate validity period.
- The current serial allocator and last-seen time are process-local. A clustered or restarted production service must replace these with durable, transactional monotonic state before serving requests.

## Request policy

The initial implementation supports SHA-256 message imprints only. The request must be DER, version 1, no larger than 64 KiB, and contain a 32-byte SHA-256 imprint with absent algorithm parameters. A supplied policy must match the configured policy. A supplied nonce is echoed unchanged. Unknown critical request extensions are rejected. The TSA certificate is always included in the CMS token, regardless of `certReq`.

The CMS `SignerInfo` includes the message digest, content type, ESS `SigningCertificateV2` certificate hash and ML-DSA-65 signature. The returned bytes are the `TimeStampToken`; an HTTP adapter should wrap it in RFC 3161 `TimeStampResp` with the appropriate PKI status and content type.

## Tests

`cargo test -p nexusq-tsa` creates a temporary TSA key/certificate, issues a token, decodes the CMS/TSTInfo structures, verifies the ML-DSA-65 CMS signed-attributes signature, checks the echoed nonce/imprint/policy, and checks rejection of malformed imprints and unsupported policies.

This crate does not perform certificate-path validation for the configured TSA certificate; the application must validate trust and provisioning policy before constructing the authority.
